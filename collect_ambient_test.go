package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func ambient(fx *fixture, probe bool) []Collector {
	return newAmbientCollectors(Options{Roots: []string{fx.home}, MaxDepth: 5, ProbeFolders: probe}, "unknown")
}

// runAmbient runs the ambient collectors, checks for leaks, and returns the snapshot.
func (f *fixture) runAmbient(cs []Collector, args ...string) (Snapshot, int) {
	f.t.Helper()
	r := f.runApp(cs, append([]string{"-json"}, args...)...)
	f.assertNoMarkers(r.stdout, r.stderr)
	plain := f.runApp(cs, args...) // the terminal summary must not leak either
	f.assertNoMarkers(plain.stdout, plain.stderr)
	if r.stdout == "" {
		f.t.Fatalf("no output; exit %d, stderr %q", r.code, r.stderr)
	}
	return decodeSnapshot(f.t, r.stdout), r.code
}

func findingsOfKind(s Snapshot, kind string) []Finding {
	var out []Finding
	for _, f := range s.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestEnvironmentFixtures(t *testing.T) {
	cases := []struct {
		name, value string
		kind        string
		class       Class
		total       float64
	}{
		{"MY_SERVICE_TOKEN", "", "env", Generic, 3},
		{"CLAUDE_CODE_MESSAGING_TOKEN", "", "env-agent", Agent, 5},
		{"DATABASE_URL", "url", "env", Generic, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newFixture(t)
			v := fx.secret("", 32)
			if c.value == "url" {
				v = "postgres://app:" + fx.secret("", 24) + "@db/app"
			}
			fx.setenv(c.name, v)
			fx.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
			fx.setenv("GOPATH", "/Users/x/go")
			fx.setenv("HOME", fx.home)
			s, _ := fx.runAmbient([]Collector{envCollector{}})
			fs := findingsOfKind(s, c.kind)
			if s.Total != c.total || len(fs) != 1 || len(fs[0].Hits) != 1 || fs[0].Hits[0].Class != c.class {
				t.Fatalf("total %v findings %+v; want %v %v", s.Total, s.Findings, c.total, c.class)
			}
			if fs[0].Location != "environment ("+string(c.class)+")" || fs[0].Hits[0].Name != c.name {
				t.Errorf("location %q, hit name %q", fs[0].Location, fs[0].Hits[0].Name)
			}
			if c.class == Agent && fs[0].Fix != fixText["agent"] {
				t.Errorf("agent token without the agent fix")
			}
		})
	}
}

func TestEnvironmentAWSSessionIsSession(t *testing.T) {
	fx := newFixture(t)
	fx.setenv("AWS_ACCESS_KEY_ID", "ASIA"+strings.ToUpper(randomAlnum(16)))
	fx.setenv("AWS_SECRET_ACCESS_KEY", fx.secret("", 40))
	fx.setenv("AWS_SESSION_TOKEN", fx.secret("", 60))
	s, _ := fx.runAmbient([]Collector{envCollector{}})
	fs := findingsOfKind(s, "env")
	if len(fs) != 1 || fs[0].Lifetime != Session {
		t.Errorf("findings %+v; want one session finding", fs)
	}
}

func TestShellFiles(t *testing.T) {
	fx := newFixture(t)
	ghp := fx.secret("ghp_", 36)
	fx.write(".zshrc", "export OPENAI_API_KEY="+fx.secret("sk-proj-", 40)+"\nexport OTHER_TOKEN=$(op read op://v/i/f)\n")
	fx.write(".zsh_history", ": 1:0;curl -H 'Authorization: Bearer "+ghp+"' https://api.github.com\n")
	fx.write(".zsh_sessions/ABC.history", "export NPM_TOKEN="+fx.secret("npm_", 36)+"\n")
	fx.write(".zsh_sessions/ABC.session", "export NPM_TOKEN="+fx.secret("npm_", 36)+"\n") // not history
	fx.write(".viminfo", ":!export GITLAB_TOKEN="+fx.secret("glpat-", 24)+"\n")
	// The same token bare in the environment: one credential across both
	// places, as the base fixture needs for hosts.yml and the history.
	fx.setenv("GITHUB_TOKEN", ghp)
	s, _ := fx.runAmbient([]Collector{shellFilesCollector{}, envCollector{}})

	rc := findingsOfKind(s, "rc-literal")
	if len(rc) != 1 || len(rc[0].Hits) != 1 || rc[0].Hits[0].Class != Service || rc[0].Location != "~/.zshrc" {
		t.Errorf(".zshrc: %+v; want one service hit, $(op read) ignored", rc)
	}
	var locs []string
	for _, f := range findingsOfKind(s, "history") {
		locs = append(locs, f.Location)
		if f.Hits[0].Class != Propagation {
			t.Errorf("%s: class %v", f.Location, f.Hits[0].Class)
		}
	}
	if strings.Join(locs, " ") != "~/.viminfo ~/.zsh_history ~/.zsh_sessions/ABC.history" {
		t.Errorf("history locations %v", locs)
	}
	// 4 credentials: sk-proj, ghp (history + environment), npm, glpat.
	if len(s.Credentials) != 4 {
		t.Errorf("%d credentials, want 4: the history hit must fingerprint the bare token", len(s.Credentials))
	}
}

func TestDotenvBaseFixture(t *testing.T) {
	fx := newFixture(t)
	fx.write("code/app/.env", "DB_PASSWORD="+fx.secret("", 24)+"\nSTRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	fx.write("code/app/.env.example", "API_KEY=your_key_here\n")
	fx.write("code/app/node_modules/x/.env", "STRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	fx.write(".env", "OTHER_TOKEN="+fx.secret("", 24)+"\n") // owned by shell-files
	s, code := fx.runAmbient(ambient(fx, false)[2:])
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	if len(s.Findings) != 1 || s.Findings[0].Location != "~/code/app/.env" {
		t.Fatalf("findings %+v; want only ~/code/app/.env", s.Findings)
	}
	if len(s.Items) != 1 || s.Items[0].Score != 8 || s.Items[0].Tier != 3 || s.Total != 8 {
		t.Errorf("items %+v total %v; want one 8.0 item", s.Items, s.Total)
	}
}

func TestDotenvCommittedAndWorktree(t *testing.T) {
	fx := newFixture(t)
	val := fx.secret("sk_live_", 24)
	fx.write("code/app/.env.development", "STRIPE_KEY="+val+"\n")
	fx.write("code/app/README.md", "x")
	fx.write("code/app/.git/index", string(gitIndex(2, ".env.development", "README.md")))
	fx.write("code/app/.git/config", "[core]\n\tbare = false\n")
	// code/app-wt is a worktree of code/app with its own index (v4).
	gd := filepath.Join(fx.home, "code/app/.git/worktrees/app-wt")
	fx.write("code/app/.git/worktrees/app-wt/index", string(gitIndex(4, ".env.development", "README.md")))
	fx.write("code/app/.git/worktrees/app-wt/commondir", "../..\n")
	fx.write("code/app-wt/.git", "gitdir: "+gd+"\n")
	fx.write("code/app-wt/.env.development", "STRIPE_KEY="+val+"\n")

	s, _ := fx.runAmbient(ambient(fx, false)[2:])
	fs := findingsOfKind(s, "dotenv")
	if len(fs) != 2 || !fs[0].Committed || !fs[1].Committed {
		t.Fatalf("dotenv findings %+v; want two, both committed", fs)
	}
	if len(s.Credentials) != 1 || s.Credentials[0].Score != 2.5 || s.Credentials[0].Class != Service {
		t.Errorf("credentials %+v; want one service 2.5", s.Credentials)
	}
	if len(s.Items) != 1 || len(s.Items[0].Locations) != 2 {
		t.Errorf("items %+v; want one item with both locations", s.Items)
	}
}

func TestDotenvUntrackedAndUnparseableIndex(t *testing.T) {
	fx := newFixture(t)
	fx.write("code/a/.env", "STRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	fx.write("code/a/.git/index", string(gitIndex(2, "README.md")))
	fx.write("code/b/.env", "STRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	fx.write("code/b/.git/index", "garbage")
	s, _ := fx.runAmbient(ambient(fx, false)[2:])
	for _, f := range findingsOfKind(s, "dotenv") {
		if f.Committed {
			t.Errorf("%s marked committed", f.Location)
		}
		unsure := strings.Contains(strings.Join(f.Notes, ";"), "could not tell")
		if unsure != (f.Location == "~/code/b/.env") || f.Confidence != Medium {
			t.Errorf("%s: notes %v confidence %v", f.Location, f.Notes, f.Confidence)
		}
	}
	if s.Total != 10 {
		t.Errorf("total %v, want 5.0 + 5.0", s.Total)
	}
}

func TestGitConfigURLCredentials(t *testing.T) {
	fx := newFixture(t)
	fx.write("code/app/README.md", "x")
	fx.write("code/app/.git/config", "[remote \"origin\"]\n\turl = https://x:"+fx.secret("ghp_", 36)+"@github.com/o/r.git\n")
	s, _ := fx.runAmbient(ambient(fx, false)[2:])
	fs := findingsOfKind(s, "git-config")
	if len(fs) != 1 || fs[0].Location != "~/code/app/.git/config" || s.Total != 10 || fs[0].Fix != fixText["github"] {
		t.Errorf("findings %+v total %v; want propagation 10.0 at the config", s.Findings, s.Total)
	}
	if strings.Contains(fs[0].Location, "github.com") {
		t.Error("location built from parsed content (A-26)")
	}
}

func TestDotenvPartialRun(t *testing.T) {
	fx := newFixture(t)
	fx.write("code/app/.env", "DB_PASSWORD="+fx.secret("", 24)+"\nSTRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	if _, code := fx.runAmbient(ambient(fx, false)[2:]); code != 0 {
		t.Fatalf("first run exit %d", code)
	}
	fx.now = fx.now.Add(time.Minute)
	cs := ambient(fx, false)[2:]
	cs[0].(*dotenvCollector).budget = 0
	r := fx.runApp(cs, "-json")
	fx.assertNoMarkers(r.stdout, r.stderr)
	if r.code != 1 {
		t.Errorf("exit %d, want 1", r.code)
	}
	s := decodeSnapshot(t, r.stdout)
	if s.Collectors["dotenv"] != Partial || s.Diff == nil || s.Diff.Delta != 0 {
		t.Fatalf("status %v diff %+v; want partial, delta 0", s.Collectors["dotenv"], s.Diff)
	}
	if len(s.Diff.Changes) != 1 || s.Diff.Changes[0].State != Unknown || s.Diff.Changes[0].Location != "~/code/app/.env" {
		t.Errorf("changes %+v; want the .env unknown", s.Diff.Changes)
	}
}

func TestDotenvProtectedFolders(t *testing.T) {
	fx := newFixture(t)
	fx.write("Documents/app/.env", "STRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	s, _ := fx.runAmbient(ambient(fx, false)[2:])
	if len(s.Findings) != 0 {
		t.Errorf("default run read Documents: %+v", s.Findings)
	}
	s, _ = fx.runAmbient(ambient(fx, true)[2:], "-probe-folders")
	if s.Total != 5 || len(s.Findings) != 1 {
		t.Errorf("-probe-folders: total %v findings %+v; want service 5.0", s.Total, s.Findings)
	}
	// Full Disk Access inferred yes from a readable Mail folder, as on a real run.
	fx.goos = "darwin"
	fx.write("Library/Mail/V10/x", "")
	fda := newAmbientCollectors(Options{Roots: []string{fx.home}, MaxDepth: 5}, inferFullDiskAccess(fx.env()))[2:]
	if s, _ = fx.runAmbient(fda); s.Total != 5 {
		t.Errorf("Full Disk Access yes: total %v, want 5.0", s.Total)
	}
}

func TestSweepProjectRegistryConfigsAndRailsKeys(t *testing.T) {
	fx := newFixture(t)
	fx.write("code/app/.npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\n")
	fx.write("code/app/.yarnrc.yml", "npmScopes:\n  acme:\n    npmAuthToken: \""+fx.secret("", 36)+"\"\n")
	fx.write("code/rails/config/master.key", fx.secret("", 32)+"\n")
	fx.write("code/rails/config/credentials/production.key", fx.secret("", 32)+"\n")
	fx.write("code/rails/lib/master.key", fx.secret("", 32)+"\n")                      // not under config/
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\n") // home: known-files owns it
	s, _ := fx.runAmbient(ambient(fx, false)[2:])
	got := map[string]string{}
	for _, f := range s.Findings {
		got[f.Location] = f.Kind + "/" + string(f.Hits[0].Class)
	}
	want := map[string]string{
		"~/code/app/.npmrc":                              "npm-token/propagation",
		"~/code/app/.yarnrc.yml":                         "yarn-token/propagation",
		"~/code/rails/config/master.key":                 "rails-key/service",
		"~/code/rails/config/credentials/production.key": "rails-key/service",
	}
	if len(got) != len(want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
}

// -roots elements are made absolute so the sweep's protected-folder and
// home-level checks see the same paths as the default run (A-57).
func TestRootsAreAbsolute(t *testing.T) {
	fx := newFixture(t)
	fx.write("Documents/app/.env", "STRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\n")
	fx.write(".env", "OTHER_TOKEN="+fx.secret("", 24)+"\n")
	fx.write("code/app/.env", "STRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	t.Chdir(fx.home)
	locations := func(args ...string) []string {
		t.Helper()
		r := fx.runApp(nil, append([]string{"-json"}, args...)...)
		fx.assertNoMarkers(r.stdout, r.stderr)
		if r.stdout == "" {
			t.Fatalf("%v: no output; exit %d, stderr %q", args, r.code, r.stderr)
		}
		var got []string
		for _, f := range decodeSnapshot(t, r.stdout).Findings {
			got = append(got, f.Kind+" "+f.Location)
		}
		return got
	}
	want := locations()
	for _, args := range [][]string{{"-roots", "."}, {"-roots", "~"}, {"-roots", ",~/,"}} {
		if got := locations(args...); !slices.Equal(got, want) {
			t.Errorf("%v: %v, want %v", args, got, want)
		}
	}
	code := locations("-roots", filepath.Join(fx.home, "code"))
	if got := locations("-roots", "~/code"); !slices.Equal(got, code) {
		t.Errorf("-roots ~/code: %v, want %v", got, code)
	}
	r := fx.runApp(nil, "-json", "-roots", "code,missing")
	if r.code != 2 || r.stdout != "" || !strings.Contains(r.stderr, "missing is not a directory") {
		t.Errorf("missing root: exit %d stdout %q stderr %q; want 2 and a message", r.code, r.stdout, r.stderr)
	}
	// Not stat'ed, even through a symlinked temp home: looking could raise the prompt.
	if r := fx.runApp(nil, "-json", "-roots", "~/Documents/missing"); r.code == 2 {
		t.Errorf("protected root: exit 2, stderr %q; want it skipped unchecked", r.stderr)
	}
}
