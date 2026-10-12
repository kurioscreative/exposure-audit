package main

// HANDOFF §11 base fixture, end to end through defaultCollectors: every
// collector together, so cross-collector merging and ordering are checked.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// baseFixture builds the §11 base fake home. It returns the fixture and the
// npm token, which the behavioral checks replace.
func baseFixture(t *testing.T) *fixture {
	fx := newFixture(t)
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\n")
	fx.write(".aws/credentials", "[default]\naws_access_key_id = "+fx.secret("AKIA", 16)+
		"\naws_secret_access_key = "+fx.secret("", 40)+
		"\n\n[tmp]\naws_access_key_id = "+fx.secret("ASIA", 16)+
		"\naws_secret_access_key = "+fx.secret("", 40)+
		"\naws_session_token = "+fx.secret("", 120)+"\n")
	ghp := fx.secret("ghp_", 36)
	fx.write(".config/gh/hosts.yml", "github.com:\n    user: me\n    oauth_token: "+ghp+"\n")
	fx.write(".zsh_history", ": 1760000000:0;curl -H 'Authorization: token "+ghp+"' https://api.github.com/user\n")
	fx.write(".zshrc", "export OPENAI_API_KEY="+fx.secret("sk-proj-", 40)+"\nexport OTHER_TOKEN=$(op read op://vault/item/token)\n")
	fx.write("code/app/.env", "DB_PASSWORD="+fx.secret("", 24)+"\nSTRIPE_KEY="+fx.secret("sk_live_", 24)+"\n")
	fx.write("code/app/.env.example", "API_KEY=your_key_here\n")
	fx.write("code/app/node_modules/x/.env", "SECRET_TOKEN="+fx.secret("", 32)+"\n")
	fx.write(".cursor/mcp.json", `{"mcpServers":{"github":{"command":"x","env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"`+fx.secret("github_pat_", 60)+`"}}}}`)
	plain, _ := fx.opensshKey("none")
	enc, _ := fx.opensshKey("aes256-ctr")
	fx.write(".ssh/id_plain", plain)
	fx.write(".ssh/id_enc", enc)
	fx.setenv("MY_SERVICE_TOKEN", fx.secret("", 32))
	return fx
}

func TestAcceptanceBaseFixture(t *testing.T) {
	fx := baseFixture(t)
	r := fx.runApp(nil, "-json")
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	s := decodeSnapshot(t, r.stdout)
	if s.Total != 68.2 || len(s.Credentials) != 11 {
		t.Errorf("total %v with %d credentials, want 68.2 with 11", s.Total, len(s.Credentials))
	}

	var got []string
	for _, it := range s.Items {
		got = append(got, strings.Join(it.Locations, "+")+"="+fmtScore(it.Score))
	}
	want := []string{
		// tier 1, 10.0 each, by location
		"~/.config/gh/hosts.yml+~/.zsh_history=10.0",
		"~/.cursor/mcp.json=10.0",
		"~/.npmrc=10.0",
		"~/.ssh/id_plain=10.0",
		// tier 2
		"~/.aws/credentials=8.0",
		"~/.aws/credentials=3.2",
		// tier 3
		"~/code/app/.env=8.0",
		"~/.zshrc=5.0",
		// tier 4, 5
		"environment: MY_SERVICE_TOKEN=3.0",
		"~/.ssh/id_enc=1.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Fix first\n got %q\nwant %q", got, want)
	}

	summary := fx.runApp(nil)
	fx.assertNoMarkers(r.stdout, r.stderr, summary.stdout, summary.stderr)
}

func TestAcceptanceBehavioralChecks(t *testing.T) {
	fx := baseFixture(t)
	fx.runApp(nil, "-json")
	fx.now = fx.now.Add(time.Minute)

	// Replacing the npm token: rotated, total unchanged.
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\n")
	s, code := fx.runJSON(nil)
	if code != 0 || s.Total != 68.2 || s.Diff.Delta != 0 || stateOf(s.Diff, "~/.npmrc") != Rotated {
		t.Errorf("rotation: exit %d total %v diff %+v", code, s.Total, s.Diff)
	}

	// Deleting .npmrc: total down by 10, resolved.
	if err := removeFile(fx, ".npmrc"); err != nil {
		t.Fatal(err)
	}
	s, code = fx.runJSON(nil)
	if code != 0 || s.Total != 58.2 || s.Diff.Delta != -10 || stateOf(s.Diff, "~/.npmrc") != Resolved {
		t.Errorf("delete: exit %d total %v diff %+v", code, s.Total, s.Diff)
	}
	fx.assertNoMarkers()
}

func stateOf(d *Diff, loc string) ChangeState {
	if d == nil {
		return ""
	}
	for _, c := range d.Changes {
		if c.Location == loc {
			return c.State
		}
	}
	return ""
}

func fmtScore(x float64) string { return fmt.Sprintf("%.1f", x) }

func removeFile(fx *fixture, rel string) error { return os.Remove(filepath.Join(fx.home, rel)) }
