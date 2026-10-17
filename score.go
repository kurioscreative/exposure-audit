package main

import (
	"cmp"
	"maps"
	"math"
	"slices"
	"strings"
)

var baseWeight = map[Class]float64{Propagation: 10, Cloud: 8, Agent: 5, Service: 5, Generic: 3}

// classRank orders classes for "highest class over those hits".
var classRank = map[Class]int{Generic: 0, Service: 1, Agent: 2, Cloud: 3, Propagation: 4}

var lifetimeMult = map[Lifetime]float64{Static: 1, Session: 0.4}
var gateMult = map[Gate]float64{Silent: 1, Windowed: 0.5, Gated: 0.1}

// hitWeight is BASE × L × G × C for one hit in one finding.
func hitWeight(f *Finding, h Hit) float64 {
	w := baseWeight[h.Class] * lifetimeMult[f.Lifetime] * gateMult[f.Gate]
	if f.Committed {
		w *= 0.5 // committed dotenv file (decision 9)
	}
	return w
}

// round1 rounds for display and JSON only. RoundToEven matches the
// prototype's Python round; math.Round would turn 6.25 into 6.3 (A-03).
func round1(x float64) float64 { return math.RoundToEven(x*10) / 10 }

// Credential is one fingerprint across all findings (decision 7).
type Credential struct {
	Fingerprint string   `json:"fingerprint"`
	Class       Class    `json:"class"`
	Score       float64  `json:"score"`
	Tier        int      `json:"tier"`
	Findings    []string `json:"findings"` // finding IDs
}

// Item is one entry in "Fix first".
type Item struct {
	Title       string   `json:"title"` // of the highest-scoring finding among them (A-39)
	Locations   []string `json:"locations"`
	Credentials []string `json:"credentials"`
	Findings    []string `json:"findings"` // IDs, so live output can show Keychain names
	Tier        int      `json:"tier"`
	Score       float64  `json:"score"`
	Fix         string   `json:"fix"`

	titleFrom string // ID of the finding the title came from, for live display
}

// credAgg is a credential before rounding.
type credAgg struct {
	fp       string
	class    Class
	score    float64
	ungated  bool // some hit is silent or windowed
	findings []*Finding
}

// aggregate groups hits by fingerprint, keeping each credential's highest
// weight and class across every location.
func aggregate(findings []Finding) map[string]*credAgg {
	creds := map[string]*credAgg{}
	for i := range findings {
		f := &findings[i]
		for _, h := range f.Hits {
			c := creds[h.Fingerprint]
			if c == nil {
				c = &credAgg{fp: h.Fingerprint, class: h.Class}
				creds[h.Fingerprint] = c
			}
			c.score = max(c.score, hitWeight(f, h))
			if classRank[h.Class] > classRank[c.class] {
				c.class = h.Class
			}
			if f.Gate != Gated {
				c.ungated = true
			}
			if !slices.Contains(c.findings, f) {
				c.findings = append(c.findings, f)
			}
		}
	}
	return creds
}

func (c *credAgg) tier() int {
	if !c.ungated {
		return 5
	}
	switch c.class {
	case Propagation:
		return 1
	case Cloud:
		return 2
	case Agent, Service:
		return 3
	}
	return 4
}

// slotKey identifies the exact set of findings, by SlotID, a credential occurs in.
func (c *credAgg) slotKey() string {
	slots := make([]string, 0, len(c.findings))
	for _, f := range c.findings {
		slots = append(slots, f.SlotID)
	}
	slices.Sort(slots)
	return strings.Join(slices.Compact(slots), ",")
}

// score derives credentials, "Fix first" items and the total from findings.
func score(findings []Finding) (creds []Credential, items []Item, total float64) {
	aggs := aggregate(findings)
	groups := map[string][]*credAgg{}
	for _, fp := range sortedKeys(aggs) {
		c := aggs[fp]
		total += c.score
		ids := make([]string, 0, len(c.findings))
		for _, f := range c.findings {
			ids = append(ids, f.ID)
		}
		slices.Sort(ids)
		creds = append(creds, Credential{fp, c.class, round1(c.score), c.tier(), ids})
		groups[c.slotKey()] = append(groups[c.slotKey()], c)
	}
	for _, k := range sortedKeys(groups) { // map order would break sortItems ties at random (A-56)
		items = append(items, makeItem(groups[k]))
	}
	sortItems(items)
	return creds, items, round1(total)
}

func makeItem(g []*credAgg) Item {
	it := Item{Tier: 5}
	fws := map[*Finding]float64{} // finding → its highest weight from this group
	for _, c := range g {
		it.Score += c.score
		it.Tier = min(it.Tier, c.tier())
		it.Credentials = append(it.Credentials, c.fp)
		for _, f := range c.findings {
			for _, h := range f.Hits {
				if h.Fingerprint == c.fp {
					fws[f] = max(fws[f], hitWeight(f, h))
				}
			}
		}
	}
	// Path order, not ID order: IDs hash fingerprints and change on rotation (A-64).
	var best *Finding
	for _, f := range slices.SortedFunc(maps.Keys(fws), compareFindings) {
		it.Locations = append(it.Locations, f.Location)
		it.Findings = append(it.Findings, f.ID)
		if best == nil || fws[f] > fws[best] {
			best = f
		}
	}
	it.Title, it.Fix, it.titleFrom = best.Title, best.Fix, best.ID
	it.Score = round1(it.Score)
	slices.Sort(it.Credentials)
	it.Locations = slices.Compact(it.Locations)
	return it
}

// compareFindings is sortFindings' order: location, kind, then ID.
func compareFindings(a, b *Finding) int {
	return cmp.Or(cmp.Compare(a.Location, b.Location), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID))
}

// sortItems orders by tier, then score descending, then location (decision 8).
func sortItems(items []Item) {
	slices.SortFunc(items, func(a, b Item) int {
		return cmp.Or(
			cmp.Compare(a.Tier, b.Tier),
			cmp.Compare(b.Score, a.Score),
			cmp.Compare(firstOr(a.Locations), firstOr(b.Locations)),
		)
	})
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

const fdaFix = "Remove it in System Settings → Privacy & Security → Full Disk Access unless something you run from this terminal needs it."

// pinnedFDAItem is the unscored tier-0 item (decision 12).
func pinnedFDAItem(app string) Item {
	return Item{Title: "Full Disk Access granted to " + app, Tier: 0, Fix: fdaFix}
}
