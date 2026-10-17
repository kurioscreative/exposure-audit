package main

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// staticCollector returns fixed findings with a fixed error.
func staticCollector(name string, err error, fs ...Finding) Collector {
	return testCollector{name, func(context.Context, *Env) ([]Finding, error) {
		out := make([]Finding, len(fs))
		copy(out, fs)
		return out, err
	}}
}

func (f *fixture) runJSON(cs []Collector, args ...string) (Snapshot, int) {
	f.t.Helper()
	r := f.runApp(cs, append([]string{"-json"}, args...)...)
	if r.stdout == "" {
		f.t.Fatalf("no output; exit %d, stderr %q", r.code, r.stderr)
	}
	f.now = f.now.Add(time.Minute)
	return decodeSnapshot(f.t, r.stdout), r.code
}

func states(d *Diff) map[ChangeState][]string {
	m := map[ChangeState][]string{}
	if d != nil {
		for _, c := range d.Changes {
			m[c.State] = append(m[c.State], c.Location)
		}
	}
	return m
}

func TestDiffResolvedAndModified(t *testing.T) {
	fx := newFixture(t)
	npm := fnd("npm-token", "~/.npmrc", Propagation, "npm1")
	gh := fnd("gh-token", "~/.config/gh/hosts.yml", Propagation, "gh1")

	first, _ := fx.runJSON([]Collector{staticCollector("files", nil, npm, gh)})
	if first.Diff != nil || first.Total != 20 {
		t.Fatalf("first run: diff %v total %v", first.Diff, first.Total)
	}

	// Deleting .npmrc: resolved, total down by 10.
	s, _ := fx.runJSON([]Collector{staticCollector("files", nil, gh)})
	if s.Diff == nil || s.Diff.Delta != -10 || fmt.Sprint(states(s.Diff)) != "map[resolved:[~/.npmrc]]" {
		t.Errorf("after delete: %+v", s.Diff)
	}

	// Replacing the token: modified, total unchanged.
	gh2 := fnd("gh-token", "~/.config/gh/hosts.yml", Propagation, "gh2")
	s, _ = fx.runJSON([]Collector{staticCollector("files", nil, gh2)})
	if s.Diff.Delta != 0 || fmt.Sprint(states(s.Diff)) != "map[modified:[~/.config/gh/hosts.yml]]" {
		t.Errorf("after rotation: %+v", s.Diff)
	}

	// Adding one back: new.
	s, _ = fx.runJSON([]Collector{staticCollector("files", nil, gh2, npm)})
	if s.Diff.Delta != 10 || fmt.Sprint(states(s.Diff)) != "map[new:[~/.npmrc]]" {
		t.Errorf("after re-adding: %+v", s.Diff)
	}
}

func TestDiffPartialCollectorIsUnknown(t *testing.T) {
	fx := newFixture(t)
	npm := fnd("npm-token", "~/.npmrc", Propagation, "npm1")
	envf := fnd("dotenv", "~/code/app/.env", Service, "stripe")
	fx.runJSON([]Collector{staticCollector("files", nil, npm), staticCollector("dotenv", nil, envf)})

	s, code := fx.runJSON([]Collector{staticCollector("files", nil, npm), staticCollector("dotenv", ErrPartial)})
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if got := fmt.Sprint(states(s.Diff)); got != "map[unknown:[~/code/app/.env]]" {
		t.Errorf("changes %s, want the .env unknown, not resolved", got)
	}
	if s.Diff.Delta != 0 {
		t.Errorf("delta %v, want 0: the partial collector's credentials are excluded", s.Diff.Delta)
	}
}

func TestDiffSkippedCollectorIsUnknownWithExitZero(t *testing.T) {
	fx := newFixture(t)
	kc := fnd("keychain-silent", "login keychain item abc", Propagation, "kc1")
	fx.runJSON([]Collector{staticCollector("keychain", nil, kc)})
	s, code := fx.runJSON([]Collector{staticCollector("keychain", ErrSkipped)})
	if code != 0 {
		t.Errorf("exit %d, want 0 for skipped", code)
	}
	if got := fmt.Sprint(states(s.Diff)); got != "map[unknown:[login keychain item abc]]" || s.Diff.Delta != 0 {
		t.Errorf("changes %s delta %v; want unknown and 0 (A-37)", got, s.Diff.Delta)
	}
}

func TestDiffComparesOnlySameContext(t *testing.T) {
	fx := newFixture(t)
	npm := fnd("npm-token", "~/.npmrc", Propagation, "npm1")
	fx.setenv("__CFBundleIdentifier", "com.example.term-a")
	fx.runJSON([]Collector{staticCollector("files", nil, npm)})

	fx.setenv("__CFBundleIdentifier", "com.example.term-b")
	s, _ := fx.runJSON([]Collector{staticCollector("files", nil)})
	if s.Diff != nil {
		t.Errorf("diffed across contexts: %+v", s.Diff)
	}
	s, _ = fx.runJSON([]Collector{staticCollector("files", nil)})
	if s.Diff == nil || s.Diff.Delta != 0 {
		t.Errorf("second run in context b should diff against the first b run: %+v", s.Diff)
	}

	fx.setenv("__CFBundleIdentifier", "com.example.term-a")
	s, _ = fx.runJSON([]Collector{staticCollector("files", nil)})
	if s.Diff == nil || s.Diff.Delta != -10 {
		t.Errorf("context a should diff against the earlier a run: %+v", s.Diff)
	}
}

// psStub serves a fake process tree: pid → (ppid, comm).
func psStub(tree map[int][2]string) func([]string) ([]byte, int) {
	return func(args []string) ([]byte, int) {
		var pid int
		fmt.Sscan(args[len(args)-1], &pid)
		e, ok := tree[pid]
		if !ok {
			return nil, 1
		}
		return []byte(fmt.Sprintf("%5s %s\n", e[0], e[1])), 0
	}
}

func TestContextKey(t *testing.T) {
	tree := map[int][2]string{
		4242: {"300", "exposure-audit"},
		300:  {"200", "-zsh"},
		200:  {"100", "/opt/homebrew/bin/claude"},
		100:  {"1", "tmux"},
	}
	cases := []struct {
		env   map[string]string
		agent bool
		want  string
	}{
		{map[string]string{"__CFBundleIdentifier": "com.mitchellh.ghostty", "TERM_PROGRAM": "tmux"}, false, "com.mitchellh.ghostty|plain"},
		{map[string]string{"TERM_PROGRAM": "Apple_Terminal"}, false, "Apple_Terminal|plain"},
		{map[string]string{}, false, "unknown|plain"},
		{map[string]string{"TERM_PROGRAM": "tmux"}, true, "tmux|agent"},
	}
	for _, c := range cases {
		fx := newFixture(t)
		for k, v := range c.env {
			fx.setenv(k, v)
		}
		tr := map[int][2]string{4242: {"1", "exposure-audit"}}
		if c.agent {
			tr = tree
		}
		fx.stubs["/bin/ps"] = psStub(tr)
		got := launchContext(context.Background(), fx.env())
		if got.Key != c.want {
			t.Errorf("env %v: key %q, want %q", c.env, got.Key, c.want)
		}
		if c.agent && strings.Join(got.Chain, " < ") != "-zsh < claude < tmux" {
			t.Errorf("chain %v", got.Chain)
		}
	}
}

func TestSummaryShowsDeltaAndItems(t *testing.T) {
	fx := newFixture(t)
	npm := fnd("npm-token", "~/.npmrc", Propagation, "npm1")
	fx.runApp([]Collector{staticCollector("files", nil, npm)})
	fx.now = fx.now.Add(time.Minute)
	r := fx.runApp([]Collector{staticCollector("files", nil)})
	for _, want := range []string{"Exposure score (lower is better): 0.0  (-10.0 since 2026-10-12 09:30 UTC)", "resolved: npm-token (~/.npmrc)"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("summary lacks %q:\n%s", want, r.stdout)
		}
	}
	r = fx.runApp([]Collector{staticCollector("files", nil, npm)})
	for _, want := range []string{"1. [10.0] npm-token", "~/.npmrc", "Fix: fix npm-token"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("summary lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestKeychainNamesOnlyInLiveOutput(t *testing.T) {
	fx := newFixture(t)
	kc := fnd("keychain-silent", "login keychain item 0123456789ab", Propagation, "kc1")
	kc.Title = "Keychain item readable without a prompt"
	kc.LiveTitle = "Keychain item gh:github.com readable without a prompt"
	kc.LiveLocation = "login keychain: gh:github.com (octo-account)"
	cs := []Collector{staticCollector("keychain", nil, kc)}

	r := fx.runApp(cs)
	if !strings.Contains(r.stdout, "gh:github.com") || !strings.Contains(r.stdout, "octo-account") {
		t.Errorf("live summary should name the item:\n%s", r.stdout)
	}
	r = fx.runApp(cs, "-json")
	for _, out := range append(fx.historyFiles(), r.stdout) {
		if strings.Contains(out, "gh:github.com") || strings.Contains(out, "octo-account") {
			t.Error("Keychain service or account name persisted (decision 16)")
		}
	}
}

// comparableTotal sums floats in map order, so an unchanged run could print
// "-0.0" when the two sums differ in the last bit.
func TestDiffUnchangedDeltaIsPositiveZero(t *testing.T) {
	var fs []Finding
	for i := range 12 {
		f := fnd("aws-session", fmt.Sprintf("~/.aws/cli/cache/%d.json", i), Cloud, fmt.Sprint("s", i))
		f.Lifetime, f.Collector = Session, "aws"
		if i%3 == 0 {
			f.Gate = Windowed
		}
		fs = append(fs, fin(f))
	}
	snap := &Snapshot{Collectors: map[string]Status{"aws": Complete}, Findings: fs}
	for range 100 {
		if d := diffSnapshots(snap, snap); d.Delta != 0 || math.Signbit(d.Delta) {
			t.Fatalf("delta %v", d.Delta)
		}
	}
}
