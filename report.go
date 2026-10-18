package main

import (
	"bytes"
	"cmp"
	_ "embed"
	"fmt"
	"html/template"
	"slices"
	"strings"
)

//go:embed report.css
var reportCSS string

const (
	summaryItems = 5
	reportItems  = 12
)

var tierLabel = map[int]string{
	0: "Pinned",
	1: "Worm vector",
	2: "Cloud / infra",
	3: "Agent or service token",
	4: "Unclassified secret",
	5: "Needs approval each time",
}

// displayItem is an item with live text: Keychain names appear here, never
// in history or -json (decision 16).
type displayItem struct {
	N         int
	Title     string
	Locations []string
	Tier      string
	Hot       bool
	Score     string
	Secrets   int
	Detail    string
	Fix       string
}

func displayItems(s *Snapshot, limit int) []displayItem {
	byID := findingsByID(s)
	var out []displayItem
	for i, it := range s.Items[:min(limit, len(s.Items))] {
		d := displayItem{N: i + 1, Title: it.Title, Tier: tierLabel[it.Tier],
			Hot: it.Tier <= 1, Secrets: len(it.Credentials), Fix: it.Fix, Score: "pinned"}
		if it.Tier > 0 {
			d.Score = fmt.Sprintf("%.1f", it.Score)
		}
		if f := byID[it.titleFrom]; f != nil { // nil for the pinned FDA item
			d.Title, d.Detail = f.DisplayTitle(), f.DisplayDetail()
		}
		for _, id := range it.Findings {
			d.Locations = append(d.Locations, byID[id].DisplayLocation())
		}
		// it.Findings is in persisted-location order; a Keychain item's live
		// location sorts differently from its slot hash.
		slices.Sort(d.Locations)
		d.Locations = slices.Compact(d.Locations) // A-58
		out = append(out, d)
	}
	return out
}

func findingsByID(s *Snapshot) map[string]*Finding {
	byID := map[string]*Finding{}
	for i := range s.Findings {
		byID[s.Findings[i].ID] = &s.Findings[i]
	}
	return byID
}

// renderSummary is the terminal output. open says the HTML report is being
// opened, so the summary points there rather than at -open.
func renderSummary(s *Snapshot, open bool) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Exposure score (lower is better): %.1f", s.Total)
	if s.Diff != nil {
		if s.Diff.Delta == 0 {
			fmt.Fprintf(&b, "  (no change since %s)", s.stamp(s.Diff.Previous))
		} else {
			fmt.Fprintf(&b, "  (%+.1f since %s)", s.Diff.Delta, s.stamp(s.Diff.Previous))
		}
	}
	fmt.Fprintf(&b, "\nFindings: %d · credentials: %d · worm vectors usable without a prompt: %d\n", len(s.Findings), len(s.Credentials), countTier(s, 1))
	fmt.Fprintf(&b, "Launched from: %s\n", launchedFrom(s))
	fmt.Fprintf(&b, "Full Disk Access: %s\n", s.FullDiskAccess)

	items := displayItems(s, summaryItems)
	if len(items) > 0 {
		b.WriteString("\nFix first:\n")
	}
	for _, it := range items {
		fmt.Fprintf(&b, "  %d. [%s] %s\n", it.N, it.Score, it.Title)
		for _, l := range it.Locations {
			fmt.Fprintf(&b, "       %s\n", l)
		}
		fmt.Fprintf(&b, "       Fix: %s\n", it.Fix)
	}
	if more := len(s.Items) - len(items); more > 0 {
		if open {
			fmt.Fprintf(&b, "  …and %d more in the report\n", more)
		} else {
			fmt.Fprintf(&b, "  …and %d more: run with -open for the full list\n", more)
		}
	}
	if groups := changeGroups(s); len(groups) > 0 {
		b.WriteString("\nChanges since last run:\n")
		for _, g := range groups {
			for _, c := range g.List {
				fmt.Fprintf(&b, "  %s: %s (%s)\n", g.State, c.Title, c.Location)
			}
		}
	}
	if s.Diff != nil && s.Diff.FDANow != "" {
		fmt.Fprintf(&b, "Full Disk Access changed: %s → %s\n", s.Diff.FDABefore, s.Diff.FDANow)
	}
	fmt.Fprintf(&b, "\nPrevention: %s\n", preventionLine(s, open))
	if notes := collectorNotes(s); len(notes) > 0 {
		fmt.Fprintf(&b, "\nCollector notes: %s\n", strings.Join(notes, "; "))
	}
	return b.Bytes()
}

func countTier(s *Snapshot, tier int) int {
	n := 0
	for _, c := range s.Credentials {
		if c.Tier == tier {
			n++
		}
	}
	return n
}

func launchedFrom(s *Snapshot) string {
	out := appName(s.Context.App)
	if s.Context.Agent != "" {
		out += " under " + s.Context.Agent
	}
	if len(s.Context.Chain) > 0 {
		out += " (" + strings.Join(s.Context.Chain, " < ") + ")"
	}
	return out
}

// preventionLine is the one-line Prevention summary (decision 19). It counts
// settings safe by default apart and names only the ones that need action,
// grouped by tool; their fixes are in the -open report, which the line
// points at unless open says it is already opening.
func preventionLine(s *Snapshot, open bool) string {
	if len(s.Prevention) == 0 {
		return "not checked"
	}
	on, safe, lastTool := 0, 0, ""
	var gaps []string
	for _, p := range s.Prevention {
		switch {
		case p.State == stateOn:
			on++
		case p.State == stateDefault:
			safe++
		case p.Tool == lastTool: // rows arrive grouped by tool
			gaps[len(gaps)-1] += " and " + p.Setting
		default:
			gaps = append(gaps, p.Tool+" "+p.Setting)
			lastTool = p.Tool
		}
	}
	if on == len(s.Prevention) {
		return fmt.Sprintf("all %d on", on)
	}
	line := fmt.Sprintf("%d of %d on", on, len(s.Prevention))
	if safe > 0 {
		line += fmt.Sprintf(", %d safe by default", safe)
	}
	if len(gaps) == 0 {
		return line
	}
	line += " · to fix: " + strings.Join(gaps, ", ")
	if !open {
		line += " (see -open)"
	}
	return line
}

// collectorNotes lists every collector that was not complete, with the
// fixed error category when there is one.
func collectorNotes(s *Snapshot) []string {
	cat := map[string]string{}
	for _, e := range s.Errors {
		cat[e.Collector] = e.Category
	}
	var notes []string
	for _, name := range sortedKeys(s.Collectors) {
		st := s.Collectors[name]
		if st == Complete {
			continue
		}
		n := name + ": " + string(st)
		if c := cat[name]; c != "" && c != string(st) {
			n += " (" + c + ")"
		}
		notes = append(notes, n)
	}
	return notes
}

type reportTile struct {
	Value string
	Label string
}

type reportChange struct {
	State string
	List  []Change
}

type reportReach struct {
	ReachRow
	Size, Count, Chip string
}

type reportFinding struct {
	Score, Title, Location, Access, Confidence, Fingerprints string
}

type reportView struct {
	CSS        template.CSS
	Time       string
	Launched   string
	Score      string
	Delta      string
	DeltaClass string
	Since      string
	Tiles      []reportTile
	FDA        string
	FDAClass   string
	Changes    []reportChange
	FDAChange  string
	Items      []displayItem
	MoreItems  int
	Reach      []reportReach
	Prevention []PreventionRow
	Keychain   *KeychainStats
	Findings   []reportFinding
	Notes      []string
}

func buildReportView(s *Snapshot) reportView {
	v := reportView{
		CSS:        template.CSS(reportCSS),
		Time:       s.stamp(s.Time),
		Launched:   launchedFrom(s),
		Score:      fmt.Sprintf("%.1f", s.Total),
		Items:      displayItems(s, reportItems),
		MoreItems:  max(0, len(s.Items)-reportItems),
		Changes:    changeGroups(s),
		Prevention: s.Prevention,
		Keychain:   s.Keychain,
		Notes:      collectorNotes(s),
	}
	if d := s.Diff; d != nil {
		switch {
		case d.Delta > 0:
			v.Delta, v.DeltaClass = fmt.Sprintf("%+.1f", d.Delta), "up"
		case d.Delta < 0:
			v.Delta, v.DeltaClass = fmt.Sprintf("%+.1f", d.Delta), "down"
		default: // unchanged is not an improvement, so not green
			v.Delta = "No change"
		}
		v.Since = s.stamp(d.Previous)
		if d.FDANow != "" {
			v.FDAChange = d.FDABefore + " → " + d.FDANow
		}
	}
	for tier := 1; tier <= 5; tier++ {
		label := tierLabel[tier] + ", usable without asking you"
		if tier == 5 {
			label = tierLabel[tier]
		}
		v.Tiles = append(v.Tiles, reportTile{fmt.Sprint(countTier(s, tier)), label})
	}
	// Beside the score rather than a sixth tile, which sat alone on a row.
	v.FDA = map[string]string{"yes": "inherited", "no": "not inherited"}[s.FullDiskAccess]
	if v.FDA == "" {
		v.FDA = s.FullDiskAccess
	}
	if s.FullDiskAccess == "yes" {
		v.FDAClass = "up"
	}

	for _, r := range s.Reach {
		rr := reportReach{ReachRow: r}
		switch r.Status {
		case "readable":
			rr.Chip = "hot"
			pre := ""
			if r.Partial {
				pre = "at least "
			}
			rr.Size, rr.Count = pre+humanBytes(r.Bytes), fmt.Sprintf("%s%d", pre, r.Files)
		case "blocked":
			rr.Chip = "cool"
		}
		v.Reach = append(v.Reach, rr)
	}
	for i := range s.Findings {
		f := &s.Findings[i]
		var w float64
		var fps []string
		for _, h := range f.Hits {
			w = max(w, hitWeight(f, h))
			fps = append(fps, h.Fingerprint)
		}
		if len(fps) > 4 {
			fps = append(fps[:4], "...")
		}
		life := "long-lived"
		if f.Lifetime == Session {
			life = "short-lived"
		}
		v.Findings = append(v.Findings, reportFinding{
			Score: fmt.Sprintf("%.1f", round1(w)), Title: f.DisplayTitle(), Location: f.DisplayLocation(),
			Access: string(f.Gate) + ", " + life, Confidence: string(f.Confidence), Fingerprints: strings.Join(fps, " "),
		})
	}
	// s.Findings is in persisted-location order; Keychain rows show live text (A-63).
	slices.SortStableFunc(v.Findings, func(a, b reportFinding) int { return cmp.Compare(a.Location, b.Location) })
	return v
}

// changeGroups groups the diff by state, for the summary and the report.
func changeGroups(s *Snapshot) []reportChange {
	if s.Diff == nil {
		return nil
	}
	byID := findingsByID(s)
	var groups []reportChange
	for _, st := range []ChangeState{New, Resolved, Modified, Unknown} {
		var list []Change
		for _, c := range s.Diff.Changes {
			// A change to a current finding shows its live text, as Fix first
			// does; resolved findings only have history's (A-62).
			if f := byID[c.ID]; f != nil {
				c.Title, c.Location = f.DisplayTitle(), f.DisplayLocation()
			}
			if c.State == st {
				list = append(list, c)
			}
		}
		if len(list) > 0 {
			groups = append(groups, reportChange{string(st), list})
		}
	}
	return groups
}

func humanBytes(n int64) string {
	f := float64(n)
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 {
			if unit == "B" {
				return fmt.Sprintf("%d B", n)
			}
			return fmt.Sprintf("%.1f %s", f, unit)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f TB", f)
}

var reportTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exposure Audit</title><style>{{.CSS}}</style></head>
<body><main>
<h1>Exposure audit</h1>
<div class="sub">{{.Time}} &middot; launched from {{.Launched}}</div>
<div class="hero"><div><div class="sub">Exposure score (lower is better)</div>
<div class="score">{{.Score}}</div>
{{if .Delta}}<div class="delta {{.DeltaClass}}">{{.Delta}} since {{.Since}}</div>{{end}}
</div><div><div class="sub">Full Disk Access</div><div class="fda {{.FDAClass}}">{{.FDA}}</div></div></div>
<div class="tiles">{{range .Tiles}}<div class="tile"><b>{{.Value}}</b><span>{{.Label}}</span></div>{{end}}</div>

{{if or .Changes .FDAChange}}<h2>Changes since last run</h2><div class="card">
{{if .FDAChange}}<div><b>Full Disk Access</b> {{.FDAChange}}</div>{{end}}
{{range .Changes}}<b>{{.State}}</b><ul>{{range .List}}<li>{{.Title}} <span class="mono">{{.Location}}</span></li>{{end}}</ul>
{{if eq .State "unknown"}}<div class="sub">Unknown means the collector did not finish in one of the two runs; those credentials are left out of the change in score.</div>{{end}}{{end}}
</div>{{end}}

<h2>Fix these first</h2>
{{range .Items}}<div class="card"><h3>{{.N}}. {{.Title}}</h3>
{{range .Locations}}<div class="loc">{{.}}</div>{{end}}
<div class="chips"><span class="chip{{if .Hot}} hot{{end}}">{{.Tier}}</span><span class="chip">{{.Score}}</span>{{if gt .Secrets 1}}<span class="chip">{{.Secrets}} secrets</span>{{end}}</div>
{{if .Detail}}<div>{{.Detail}}</div>{{end}}
<div class="fix"><b>Fix:</b> {{.Fix}}</div></div>
{{else}}<div class="card">Nothing found. Run it from the terminal you actually install packages from to be sure.</div>{{end}}
{{if .MoreItems}}<div class="sub">{{.MoreItems}} more not shown here; every finding is listed under All findings below.</div>{{end}}

<h2>Data reach</h2><div class="sub">What the same process can read beyond credentials. Not included in the score.</div>
<div class="card tw"><table><tr><th>Location</th><th>Status</th><th>Size</th><th>Files</th><th>Note</th></tr>
{{range .Reach}}<tr><td>{{.Label}}<div class="mono">{{.Path}}</div></td><td><span class="chip {{.Chip}}">{{.Status}}</span></td><td class="n">{{.Size}}</td><td class="n">{{.Count}}</td><td>{{.Note}}</td></tr>
{{else}}<tr><td colspan="5">Not measured on this system.</td></tr>{{end}}
</table></div>

<h2>Prevention</h2><div class="sub">Whether package managers run install scripts. Not included in the score.</div>
<div class="card tw"><table><tr><th>Tool</th><th>Setting</th><th>State</th><th>Fix</th></tr>
{{range .Prevention}}<tr><td>{{.Tool}}</td><td class="mono key">{{.Setting}}</td><td><span class="chip{{if eq .State "on"}} cool{{else if eq .State "off"}} hot{{else if eq .State "not configured"}} warm{{end}}">{{.State}}</span></td><td>{{.Fix}}</td></tr>
{{else}}<tr><td colspan="4">Not checked.</td></tr>{{end}}
</table></div>

{{with .Keychain}}<h2>Login keychain</h2><div class="card">{{.Total}} password item{{if ne .Total 1}}s{{end}}: <b>{{.Silent}} readable without a prompt</b>, {{.AppGated}} gated to specific apps, {{.Unknown}} undetermined.</div>{{end}}

<h2>All findings ({{len .Findings}})</h2><div class="card tw"><table><tr><th>Score</th><th>Finding</th><th>Location</th><th>Access</th><th>Fingerprints</th></tr>
{{range .Findings}}<tr><td class="n">{{.Score}}</td><td>{{.Title}}{{if ne .Confidence "high"}} <span class="chip">{{.Confidence}} confidence</span>{{end}}</td><td class="mono">{{.Location}}</td><td>{{.Access}}</td><td class="mono">{{.Fingerprints}}</td></tr>{{end}}
</table></div>

<h2>How to read this</h2><div class="card"><ul>
<li>This reflects the terminal it was launched from. Rerun it from every terminal and IDE you install packages in; their permissions differ.</li>
<li>Each credential is scored once, at the highest weight it earns in any location: worm vector 10, cloud 8, coding-agent and service tokens 5, unclassified 3; × 0.4 if short-lived; × 0.5 if an approval is cached for a while; × 0.1 if it needs your approval each time; × 0.5 for a dotenv file committed to git.</li>
<li>"Fix these first" is ordered by tier, then score: a worm vector always ranks above cloud keys, whatever their total. Full Disk Access on the launching terminal is pinned on top and not scored.</li>
<li>Offline only: it cannot tell whether a token is still valid or what it is scoped to.</li>
<li>Fingerprints are salted with a key that stays on this machine. They let you spot the same secret in several places and track it across runs.</li>
<li>Keychain results come from access lists and partition lists, not from reading items, so treat them as likely rather than certain.</li>
<li>~/.exposure-audit keeps run history: titles and locations of what was found (never values or Keychain names). It is readable by the same kind of script this tool models. Delete it if that matters more to you than tracking progress.</li>
<li>This page maps where your secrets live. It is deleted a few seconds after opening; keep any copy local.</li></ul>
{{if .Notes}}<details open><summary>Collector notes ({{len .Notes}})</summary><ul>{{range .Notes}}<li>{{.}}</li>{{end}}</ul></details>{{end}}
</div>
</main></body></html>
`))

func renderReport(s *Snapshot) ([]byte, error) {
	var b bytes.Buffer
	err := reportTmpl.Execute(&b, buildReportView(s))
	return b.Bytes(), err
}
