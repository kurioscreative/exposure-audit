package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type ChangeState string

const (
	New      ChangeState = "new"
	Resolved ChangeState = "resolved"
	Rotated  ChangeState = "rotated" // same SlotID, different ID (includes a changed Keychain mdat)
	Unknown  ChangeState = "unknown" // its collector was not complete in one of the runs (A-13)
)

type Change struct {
	State    ChangeState `json:"state"`
	ID       string      `json:"id"`
	Title    string      `json:"title"`
	Location string      `json:"location"`
}

// Diff compares a run with the most recent earlier run in the same context.
type Diff struct {
	Previous  time.Time `json:"previous"`
	Delta     float64   `json:"delta"` // excludes credentials held only by unknown findings
	Changes   []Change  `json:"changes,omitempty"`
	FDABefore string    `json:"fda_before,omitempty"` // set only when Full Disk Access changed (A-06)
	FDANow    string    `json:"fda_now,omitempty"`
}

func complete(s *Snapshot, collector string) bool { return s.Collectors[collector] == Complete }

// diffSnapshots classifies every finding of both runs.
func diffSnapshots(prev, cur *Snapshot) *Diff {
	d := &Diff{Previous: prev.Time}
	prevByID, prevBySlot := index(prev.Findings)
	curByID, curBySlot := index(cur.Findings)
	unknown := map[string]bool{} // finding IDs, from either run

	for _, f := range cur.Findings {
		_, sameID := prevByID[f.ID]
		_, sameSlot := prevBySlot[f.SlotID]
		switch {
		case !complete(prev, f.Collector) || !complete(cur, f.Collector):
			if !sameID {
				d.add(Unknown, f)
			}
			unknown[f.ID] = true
		case sameID:
		case sameSlot:
			d.add(Rotated, f)
		default:
			d.add(New, f)
		}
	}
	for _, f := range prev.Findings {
		if _, ok := curByID[f.ID]; ok {
			continue
		}
		if !complete(prev, f.Collector) || !complete(cur, f.Collector) {
			unknown[f.ID] = true
			if _, rot := curBySlot[f.SlotID]; !rot {
				d.add(Unknown, f)
			}
			continue
		}
		if _, rot := curBySlot[f.SlotID]; !rot {
			d.add(Resolved, f)
		}
	}
	// Round each total first: they are float sums in map order, and an
	// unchanged run must give 0, not -0.0.
	d.Delta = round1(round1(comparableTotal(cur.Findings, unknown)) - round1(comparableTotal(prev.Findings, unknown)))
	if prev.FullDiskAccess != cur.FullDiskAccess {
		d.FDABefore, d.FDANow = prev.FullDiskAccess, cur.FullDiskAccess
	}
	return d
}

func (d *Diff) add(s ChangeState, f Finding) {
	d.Changes = append(d.Changes, Change{s, f.ID, f.Title, f.Location})
}

func index(fs []Finding) (byID, bySlot map[string]*Finding) {
	byID, bySlot = map[string]*Finding{}, map[string]*Finding{}
	for i := range fs {
		byID[fs[i].ID] = &fs[i]
		bySlot[fs[i].SlotID] = &fs[i]
	}
	return byID, bySlot
}

// comparableTotal sums the credentials that at least one finding of known
// status holds. A credential held only by unknown findings is left out of
// both totals, so a skipped or partial collector never looks like progress.
func comparableTotal(fs []Finding, unknown map[string]bool) float64 {
	var t float64
	for _, c := range aggregate(fs) {
		if slices.ContainsFunc(c.findings, func(f *Finding) bool { return !unknown[f.ID] }) {
			t += c.score
		}
	}
	return t
}

// previousSnapshot returns the most recent snapshot with the same context
// key, or nil. Unreadable or foreign-schema files are skipped.
func previousSnapshot(stateDir, key string) *Snapshot {
	paths, _ := filepath.Glob(filepath.Join(stateDir, "history", "*.json"))
	slices.SortFunc(paths, func(a, b string) int { return compareStamp(b, a) })
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var s Snapshot
		if json.Unmarshal(b, &s) != nil || s.Schema != snapshotSchema || s.Context.Key != key {
			continue
		}
		return &s
	}
	return nil
}

// compareStamp orders "STAMP.json" < "STAMP-2.json" < "STAMP-10.json".
func compareStamp(a, b string) int {
	sa, na := splitStamp(filepath.Base(a))
	sb, nb := splitStamp(filepath.Base(b))
	if c := strings.Compare(sa, sb); c != 0 {
		return c
	}
	return na - nb
}

func splitStamp(name string) (string, int) {
	name = strings.TrimSuffix(name, ".json")
	stamp, n, ok := strings.Cut(name, "-")
	if !ok {
		return stamp, 1
	}
	i, _ := strconv.Atoi(n)
	return stamp, i
}
