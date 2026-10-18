package main

import (
	"context"
	"fmt"
	"os"
	"slices"
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
	if !strings.Contains(r.stderr, "Opened the report in your browser") {
		t.Errorf("-open waits without saying why: %q", r.stderr)
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
		"Prevention: 1 of 2 settings on · to fix: Yarn enableScripts (see -open)",
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

// An item's locations display in path order. Finding IDs hash the secret's
// fingerprint, so ordering by ID could reshuffle them when a secret rotated.
func TestItemLocationsDisplayInPathOrder(t *testing.T) {
	for i := range 20 {
		fp := fmt.Sprintf("gh%d", i) // each fingerprint stands for one rotation
		s := &Snapshot{Findings: []Finding{
			fin(fnd("gh-token", "~/.zsh_history", Propagation, fp)),
			fin(fnd("gh-token", "~/.config/gh/hosts.yml", Propagation, fp)),
		}}
		_, s.Items, _ = score(s.Findings)
		got := displayItems(s, 1)[0].Locations
		if want := []string{"~/.config/gh/hosts.yml", "~/.zsh_history"}; !slices.Equal(got, want) {
			t.Fatalf("fingerprint %s: locations %q, want %q", fp, got, want)
		}
	}
}

// Two findings in one item at the same location show it once (A-58).
func TestItemLocationsDisplayOnce(t *testing.T) {
	s := &Snapshot{Findings: []Finding{
		fin(fnd("aws-static", "~/.aws/credentials", Cloud, "ak")),
		with(fnd("aws-session", "~/.aws/credentials", Cloud, "ak"), func(f *Finding) { f.Lifetime = Session }),
	}}
	_, s.Items, _ = score(s.Findings)
	if got := displayItems(s, 1)[0].Locations; !slices.Equal(got, []string{"~/.aws/credentials"}) {
		t.Errorf("locations %q, want one", got)
	}
}

// All findings sorts by the location shown, not the persisted slot hash (A-63).
func TestReportFindingsInDisplayOrder(t *testing.T) {
	kc := func(slot, live string) Finding {
		f := fin(fnd("keychain-silent", "login keychain item "+slot, Propagation, slot))
		f.LiveLocation = "login keychain: " + live
		return f
	}
	s := &Snapshot{Findings: []Finding{kc("00", "zz"), kc("ff", "aa")}}
	var got []string
	for _, f := range buildReportView(s).Findings {
		got = append(got, f.Location)
	}
	if want := []string{"login keychain: aa", "login keychain: zz"}; !slices.Equal(got, want) {
		t.Errorf("rows %q, want %q", got, want)
	}
	if s.Findings[0].Location != "login keychain item 00" {
		t.Error("view sort reordered the snapshot")
	}
}

// Changes for current findings show live text; resolved ones keep history's (A-62).
func TestReportChangesShowLiveText(t *testing.T) {
	kc := fin(fnd("keychain-silent", "login keychain item 00", Propagation, "kc"))
	kc.LiveTitle, kc.LiveLocation = "gh token", "login keychain: gh:github.com"
	s := &Snapshot{Findings: []Finding{kc}, Diff: &Diff{Changes: []Change{
		{New, kc.ID, kc.Title, kc.Location},
		{Resolved, "gone", "npm auth token", "~/.npmrc"},
	}}}
	v := buildReportView(s)
	if got := v.Changes[0].List[0]; got.Title != "gh token" || got.Location != "login keychain: gh:github.com" {
		t.Errorf("new change %+v, want live text", got)
	}
	if got := v.Changes[1].List[0]; got.Title != "npm auth token" || got.Location != "~/.npmrc" {
		t.Errorf("resolved change %+v, want persisted text", got)
	}
	if s.Diff.Changes[0].Location != "login keychain item 00" {
		t.Error("view changed the persisted diff")
	}
}

// The summary says how many items it left out, names each change, and says
// which way the score goes.
func TestSummaryNamesChangesAndHiddenItems(t *testing.T) {
	var fs []Finding
	for i := range 7 {
		fs = append(fs, fin(fnd("gh-token", fmt.Sprintf("~/f%d", i), Propagation, fmt.Sprint("fp", i))))
	}
	s := &Snapshot{Findings: fs, Diff: &Diff{Changes: []Change{
		{Resolved, "gone", "npm auth token", "~/.npmrc"},
		{Modified, fs[0].ID, "gh-token", "~/f0"},
	}}}
	s.Credentials, s.Items, s.Total = score(s.Findings)
	out := string(renderSummary(s, false))
	for _, want := range []string{
		"Exposure score (lower is better): ",
		"  …and 2 more: run with -open for the full list\n",
		"Changes since last run:\n  resolved: npm auth token (~/.npmrc)\n  modified: gh-token (~/f0)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if out := string(renderSummary(s, true)); !strings.Contains(out, "  …and 2 more in the report\n") {
		t.Errorf("-open run still points at -open:\n%s", out)
	}
	s.Items = s.Items[:summaryItems]
	if out := string(renderSummary(s, false)); strings.Contains(out, "more:") {
		t.Errorf("nothing hidden, but summary says so:\n%s", out)
	}
}

func TestSummaryPreventionAllOn(t *testing.T) {
	s := &Snapshot{Prevention: []PreventionRow{{Tool: "npm", Setting: "ignore-scripts", State: stateOn}}}
	if got := preventionLine(s); got != "all 1 on" {
		t.Errorf("got %q", got)
	}
}

func TestReportCopy(t *testing.T) {
	s := &Snapshot{
		Keychain:   &KeychainStats{Total: 1, Silent: 1},
		Prevention: []PreventionRow{{Tool: "npm", Setting: "ignore-scripts", State: stateOff, Fix: "x"}},
		Diff:       &Diff{Changes: []Change{{Resolved, "gone", "npm auth token", "~/.npmrc"}}},
	}
	out, _ := renderReport(s)
	r := string(out)
	for _, want := range []string{"1 password item: ", "usable without asking you", `<span class="chip hot">off</span>`} {
		if !strings.Contains(r, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	for _, bad := range []string{"1 password items", "silent or windowed", "Unknown means"} {
		if strings.Contains(r, bad) {
			t.Errorf("report has %q", bad)
		}
	}
	s.Diff.Changes = append(s.Diff.Changes, Change{Unknown, "u", "AWS keys", "~/.aws/credentials"})
	if out, _ := renderReport(s); !strings.Contains(string(out), "Unknown means") {
		t.Error("unknown change without its explanation")
	}
}

// The launching app shows the name System Settings uses, not its bundle
// identifier; an unlisted identifier shows as is.
func TestLaunchedFromShowsAppName(t *testing.T) {
	for id, want := range map[string]string{
		"com.mitchellh.ghostty": "Ghostty (zsh < tmux)",
		"com.example.term":      "com.example.term (zsh < tmux)",
	} {
		s := &Snapshot{Context: Context{App: id, Chain: []string{"zsh", "tmux"}}}
		if got := launchedFrom(s); got != want {
			t.Errorf("%s: got %q, want %q", id, got, want)
		}
	}
	if got := pinnedFDAItem(appName("com.googlecode.iterm2")).Title; got != "Full Disk Access granted to iTerm2" {
		t.Errorf("pinned item %q", got)
	}
}
