package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAIConfigMCPToken(t *testing.T) {
	fx := newFixture(t)
	pat := fx.secret("github_pat_", 60)
	fx.write(".cursor/mcp.json", `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"`+pat+`"}}}}`)
	fx.write(".claude/settings.json", `{"theme":"dark","author":"someone"}`)

	r := fx.runApp([]Collector{aiConfigCollector{}}, "-json")
	s := decodeSnapshot(t, r.stdout)
	fx.assertNoMarkers(r.stdout, r.stderr)
	if r.code != 0 || len(s.Findings) != 1 {
		t.Fatalf("exit %d, findings %+v", r.code, s.Findings)
	}
	f := s.Findings[0]
	if f.Location != "~/.cursor/mcp.json" || f.Kind != "ai-config" || f.Confidence != Medium || f.Fix != fixText["ai"] {
		t.Errorf("finding %+v", f)
	}
	if s.Total != 10 || len(s.Credentials) != 1 || s.Credentials[0].Class != Propagation {
		t.Errorf("total %v credentials %+v; want propagation 10.0", s.Total, s.Credentials)
	}
	r = fx.runApp([]Collector{aiConfigCollector{}})
	fx.assertNoMarkers(r.stdout, r.stderr)
}

func TestOpCLIDetection(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	dir := t.TempDir()
	c := &opCLICollector{appPath: filepath.Join(dir, "1Password.app"), opPaths: []string{filepath.Join(dir, "brew-op"), filepath.Join(dir, "local-op")}}

	if s, _ := fx.runJSON([]Collector{c}); len(s.Findings) != 0 {
		t.Errorf("finding without the app or op: %+v", s.Findings)
	}
	os.Mkdir(c.appPath, 0o755)
	if s, _ := fx.runJSON([]Collector{c}); len(s.Findings) != 0 {
		t.Errorf("finding with the app but no op: %+v", s.Findings)
	}
	os.WriteFile(c.opPaths[1], []byte("binary"), 0o755)
	s, code := fx.runJSON([]Collector{c})
	if code != 0 || len(s.Findings) != 1 {
		t.Fatalf("exit %d findings %+v", code, s.Findings)
	}
	f := s.Findings[0]
	if f.Kind != "op-cli" || f.Gate != Windowed || f.Confidence != Low || f.Hits[0].Class != Propagation {
		t.Errorf("finding %+v", f)
	}
	if s.Total != 5 || s.Items[0].Tier != 1 {
		t.Errorf("total %v tier %d; want propagation windowed 5.0, tier 1", s.Total, s.Items[0].Tier)
	}
	fx.mu.Lock()
	defer fx.mu.Unlock()
	for _, c := range fx.ran {
		if c.Path != "/bin/ps" { // ps is the context key, not this collector
			t.Errorf("executed %q; the op collector must only stat", c.Path)
		}
	}
}

func TestOpCLISkippedOffMac(t *testing.T) {
	fx := newFixture(t)
	s, code := fx.runJSON([]Collector{newOpCLICollector()})
	if code != 0 || s.Collectors["1password-cli"] != Skipped {
		t.Errorf("exit %d status %q; want 0 and skipped on linux", code, s.Collectors["1password-cli"])
	}
}

func preventionState(s Snapshot, tool, setting string) string {
	for _, r := range s.Prevention {
		if r.Tool == tool && r.Setting == setting {
			return r.State
		}
	}
	return "missing"
}

func TestPreventionNpmIgnoreScripts(t *testing.T) {
	fx := newFixture(t)
	tok := fx.secret("npm_", 36)
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+tok+"\nignore-scripts=true\n")
	r := fx.runApp([]Collector{&preventionCollector{}}, "-json")
	s := decodeSnapshot(t, r.stdout)
	fx.assertNoMarkers(r.stdout, r.stderr)
	if got := preventionState(s, "npm", "ignore-scripts"); got != stateOn {
		t.Errorf("npm ignore-scripts %q, want on", got)
	}
	if s.Total != 0 || len(s.Findings) != 0 {
		t.Errorf("prevention changed the score: total %v findings %d", s.Total, len(s.Findings))
	}
	for _, row := range s.Prevention {
		if row.State == stateOn && row.Fix != "" || row.State != stateOn && row.Fix == "" {
			t.Errorf("row %+v: fix only when not on", row)
		}
	}
}

func TestPreventionAllTools(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write(".npmrc", "ignore-scripts=false\nmin-release-age=3\n")
	fx.write(".yarnrc.yml", "enableScripts: false\nnpmMinimalAgeGate: \"0d\"\n")
	fx.write("Library/Preferences/pnpm/rc", "minimum-release-age=0\nignore-scripts=true\n")
	fx.write("Library/Preferences/pnpm/config.yaml", "minimumReleaseAge: 4320\ndangerouslyAllowAllBuilds: true\n")
	fx.write(".bunfig.toml", "[install]\nignoreScripts = true # keep\n\n[run]\nminimumReleaseAge = 0\n")
	s, _ := fx.runJSON([]Collector{&preventionCollector{}})
	want := map[[2]string]string{
		{"npm", "ignore-scripts"}:             stateOff,
		{"npm", "min-release-age"}:            stateOn,
		{"Yarn", "enableScripts"}:             stateOn,
		{"Yarn", "npmMinimalAgeGate"}:         stateOff,
		{"pnpm", "ignoreScripts"}:             stateOn, // from rc, kebab-case
		{"pnpm", "dangerouslyAllowAllBuilds"}: stateOff,
		{"pnpm", "minimumReleaseAge"}:         stateOn, // config.yaml wins over rc
		{"Bun", "install.ignoreScripts"}:      stateOn,
		{"Bun", "install.minimumReleaseAge"}:  stateNotConfigured, // set under [run], not [install]
	}
	for k, v := range want {
		if got := preventionState(s, k[0], k[1]); got != v {
			t.Errorf("%s %s = %q, want %q", k[0], k[1], got, v)
		}
	}
	if len(s.Prevention) != len(want) {
		t.Errorf("%d rows, want %d", len(s.Prevention), len(want))
	}
}

func TestPreventionNothingConfigured(t *testing.T) {
	fx := newFixture(t)
	r := fx.runApp([]Collector{&preventionCollector{}}, "-json")
	s := decodeSnapshot(t, r.stdout)
	for _, row := range s.Prevention {
		if row.State != stateNotConfigured || !strings.Contains(row.Fix, " ") {
			t.Errorf("row %+v", row)
		}
	}
}
