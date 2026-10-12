package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
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

func renderSummary(s *Snapshot) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Exposure score: %.1f\n", 0.0)
	fmt.Fprintf(&b, "Findings: %d\n", len(s.Findings))
	writeCollectorNotes(&b, s)
	return b.Bytes()
}

func writeCollectorNotes(b *bytes.Buffer, s *Snapshot) {
	for _, name := range sortedKeys(s.Collectors) {
		if st := s.Collectors[name]; st != Complete {
			fmt.Fprintf(b, "Collector %s: %s\n", name, st)
		}
	}
}
