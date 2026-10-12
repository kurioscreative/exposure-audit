package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// sectionCollector supplies unscored sections the way the prevention and
// Keychain collectors will.
type sectionCollector struct {
	prevention []PreventionRow
	keychain   *KeychainStats
}

func (sectionCollector) Name() string { return "sections" }
func (sectionCollector) Collect(context.Context, *Env) ([]Finding, error) {
	return nil, nil
}
func (c sectionCollector) Section(s *Snapshot) {
	s.Prevention, s.Keychain = c.prevention, c.keychain
}

func reportFixture(t *testing.T) (*fixture, []Collector, *string) {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Application Support/Slack/cache", "0123456789")
	fx.write("Library/Mail/V10/x", "mail")
	tok := fx.secret("npm_", 36)
	var report string
	fx.stubs["/usr/bin/open"] = func(a []string) ([]byte, int) {
		b, _ := os.ReadFile(a[0])
		report = string(b)
		return nil, 0
	}
	npm := Finding{Kind: "npm-token", Title: "npm auth token", Location: "~/.npmrc", Fix: fixText["npm"]}
	kc := fnd("keychain-silent", "login keychain item 0123456789ab", Propagation, "kc1")
	kc.Title = "Keychain item readable without a prompt"
	kc.LiveLocation = "login keychain: gh:github.com (octo-account)"
	sess := with(fnd("aws-session", "~/.aws/credentials", Cloud, "sess"), func(f *Finding) { f.Lifetime = Session; f.Confidence = Medium })
	files := testCollector{"files", func(_ context.Context, env *Env) ([]Finding, error) {
		f := npm
		f.Hits = []Hit{{Fingerprint: env.Fingerprint(NewSecret([]byte(tok))), Class: Propagation}}
		return []Finding{f, kc, sess}, nil
	}}
	sections := sectionCollector{
		prevention: []PreventionRow{
			{Tool: "npm", Setting: "ignore-scripts", State: "on"},
			{Tool: "Yarn", Setting: "enableScripts", State: "not configured", Fix: "Set enableScripts: false."},
		},
		keychain: &KeychainStats{Total: 147, Silent: 12, AppGated: 120, Unknown: 15},
	}
	cs := append([]Collector{files, sections}, newReachCollectors(Options{}, "yes")...)
	return fx, cs, &report
}

func TestReportRendersEverySection(t *testing.T) {
	fx, cs, report := reportFixture(t)
	// A first run without Mail access, so the second has changes and an FDA change.
	os.RemoveAll(fx.home + "/Library/Mail")
	fx.runApp(cs[:1])
	fx.write("Library/Mail/V10/x", "mail")
	fx.now = fx.now.AddDate(0, 0, 1)
	r := fx.runApp(cs, "-open")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"<h1>Exposure audit</h1>",
		"Changes since last run",
		"Full Disk Access</b> unknown → yes",
		"Fix these first",
		"1. Full Disk Access granted to unknown",
		"Worm vector",
		"login keychain: gh:github.com (octo-account)", // live output may name Keychain items
		"Data reach", "Slack data", "readable", "10 B",
		"Prevention", "ignore-scripts", "Set enableScripts: false.",
		"Login keychain", "147 password items", "12 readable without a prompt",
		"All findings (3)", "medium confidence", "short-lived",
		"How to read this", "readable by the same kind of script this tool models",
	} {
		if !strings.Contains(*report, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// Prevention after Data reach, as in HANDOFF §7.
	if strings.Index(*report, "<h2>Prevention</h2>") < strings.Index(*report, "<h2>Data reach</h2>") {
		t.Error("Prevention section precedes Data reach")
	}
	fx.assertNoMarkers(r.stdout, r.stderr, *report)
}

func TestReportEscapesParsedText(t *testing.T) {
	s := &Snapshot{Findings: []Finding{{ID: "a", Title: "<script>x</script>", Location: "~/a"}}}
	out, err := renderReport(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "<script>x") {
		t.Error("finding text not escaped")
	}
}

func TestSummaryPreventionAndNotes(t *testing.T) {
	fx, cs, _ := reportFixture(t)
	partial := testCollector{"dotenv", func(context.Context, *Env) ([]Finding, error) { return nil, ErrPartial }}
	r := fx.runApp(append(cs, partial))
	for _, want := range []string{
		"Prevention: npm ignore-scripts on · Yarn enableScripts not configured",
		"Collector notes: dotenv: partial",
		"Full Disk Access: yes",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("summary lacks %q:\n%s", want, r.stdout)
		}
	}
	fx.assertNoMarkers(r.stdout, r.stderr)

	empty := newFixture(t)
	if r := empty.runApp([]Collector{}); !strings.Contains(r.stdout, "Prevention: not checked") {
		t.Errorf("summary without prevention data:\n%s", r.stdout)
	}
}
