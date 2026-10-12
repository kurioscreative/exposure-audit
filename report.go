package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
)

//go:embed report.css
var reportCSS string

var reportTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exposure Audit</title><style>{{.CSS}}</style></head>
<body><main>
<h1>Exposure audit</h1>
<div class="sub">{{.Snap.Time.UTC.Format "2006-01-02 15:04 UTC"}}</div>
</main></body></html>
`))

func renderReport(s *Snapshot) ([]byte, error) {
	var b bytes.Buffer
	err := reportTmpl.Execute(&b, struct {
		CSS  template.CSS
		Snap *Snapshot
	}{template.CSS(reportCSS), s})
	return b.Bytes(), err
}

const summaryItems = 5

func renderSummary(s *Snapshot) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Exposure score: %.1f", s.Total)
	if s.Diff != nil {
		fmt.Fprintf(&b, "  (%+.1f since %s)", s.Diff.Delta, s.Diff.Previous.Format("2006-01-02 15:04 UTC"))
	}
	worm := 0
	for _, c := range s.Credentials {
		if c.Tier == 1 {
			worm++
		}
	}
	fmt.Fprintf(&b, "\nFindings: %d · credentials: %d · worm vectors usable without a prompt: %d\n", len(s.Findings), len(s.Credentials), worm)
	fmt.Fprintf(&b, "Launched from: %s", s.Context.App)
	if s.Context.Agent != "" {
		fmt.Fprintf(&b, " under %s", s.Context.Agent)
	}
	if len(s.Context.Chain) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(s.Context.Chain, " < "))
	}
	fmt.Fprintf(&b, "\nFull Disk Access: %s\n", s.FullDiskAccess)

	byID := map[string]*Finding{}
	for i := range s.Findings {
		byID[s.Findings[i].ID] = &s.Findings[i]
	}
	if len(s.Items) > 0 {
		b.WriteString("\nFix first:\n")
	}
	for i, it := range s.Items[:min(summaryItems, len(s.Items))] {
		title, locs := it.Title, it.Locations
		if f := byID[it.titleFrom]; f != nil {
			title = f.DisplayTitle()
		}
		if len(it.Findings) > 0 {
			locs = nil
			for _, id := range it.Findings {
				locs = append(locs, byID[id].DisplayLocation())
			}
		}
		score := "pinned"
		if it.Tier > 0 {
			score = fmt.Sprintf("%.1f", it.Score)
		}
		fmt.Fprintf(&b, "  %d. [%s] %s\n", i+1, score, title)
		for _, l := range locs {
			fmt.Fprintf(&b, "       %s\n", l)
		}
		fmt.Fprintf(&b, "       Fix: %s\n", it.Fix)
	}
	if s.Diff != nil && len(s.Diff.Changes) > 0 {
		counts := map[ChangeState]int{}
		for _, c := range s.Diff.Changes {
			counts[c.State]++
		}
		var parts []string
		for _, st := range []ChangeState{New, Resolved, Rotated, Unknown} {
			if counts[st] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[st], st))
			}
		}
		fmt.Fprintf(&b, "\nChanges since last run: %s\n", strings.Join(parts, ", "))
	}
	if s.Diff != nil && s.Diff.FDANow != "" {
		fmt.Fprintf(&b, "Full Disk Access changed: %s → %s\n", s.Diff.FDABefore, s.Diff.FDANow)
	}
	writeCollectorNotes(&b, s)
	return b.Bytes()
}

func writeCollectorNotes(b *bytes.Buffer, s *Snapshot) {
	var notes []string
	for _, name := range sortedKeys(s.Collectors) {
		if st := s.Collectors[name]; st != Complete {
			notes = append(notes, name+": "+string(st))
		}
	}
	if len(notes) > 0 {
		fmt.Fprintf(b, "\nCollector notes: %s\n", strings.Join(notes, "; "))
	}
}
