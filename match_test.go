package main

import (
	"testing"
)

func TestClassForNameUsesSegments(t *testing.T) {
	cases := map[string]Class{
		"HIGH_WATER_TOKEN":            Generic, // GH_ inside HIGH_ (A-17)
		"GH_TOKEN":                    Propagation,
		"NODE_AUTH_TOKEN":             Propagation,
		"github-token":                Propagation,
		"AWS_SECRET_ACCESS_KEY":       Cloud,
		"KUBECONFIG_TOKEN":            Generic,
		"TF_TOKEN_app_terraform_io":   Cloud,
		"CLAUDE_CODE_MESSAGING_TOKEN": Agent,
		"CODEX_API_KEY":               Agent,
		"MY_CURSOR_TOKEN":             Generic, // agent prefixes match leading segments only
		"MY_SERVICE_TOKEN":            Generic,
	}
	for name, want := range cases {
		if got := classForName(name); got != want {
			t.Errorf("classForName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestExtractSecrets(t *testing.T) {
	fx := newFixture(t)
	ghp := fx.secret("ghp_", 36)
	db := fx.secret("", 24)
	svc := fx.secret("", 32)
	text := "export GITHUB_TOKEN=" + ghp + "\n" +
		"export MY_SERVICE_TOKEN=" + svc + "\n" +
		"export OTHER_TOKEN=$(op read op://vault/item)\n" +
		"API_KEY=your_key_here\n" +
		"DATABASE_URL=postgres://app:" + db + "@db/app\n" +
		"curl -H 'Authorization: token " + ghp + "'\n"
	ms := extractSecrets([]byte(text))
	if len(ms) != 3 {
		t.Fatalf("got %d matches, want 3 (ghp once, service, url password)", len(ms))
	}
	env := fx.env()
	got := map[string]Match{}
	for _, m := range ms {
		got[env.Fingerprint(m.Value)] = m
	}
	fp := func(v string) string { return env.Fingerprint(NewSecret([]byte(v))) }
	if m := got[fp(ghp)]; m.Class != Propagation || m.Name != "GITHUB_TOKEN" {
		t.Errorf("ghp match %+v", m)
	}
	if m := got[fp(svc)]; m.Class != Generic || m.Name != "MY_SERVICE_TOKEN" {
		t.Errorf("service match %+v", m)
	}
	if m := got[fp(db)]; m.Class != Generic || m.Name != "DATABASE_URL" {
		t.Errorf("url match %+v", m)
	}
}

func TestURLCredentialClassByHost(t *testing.T) {
	fx := newFixture(t)
	tok := fx.secret("", 20)
	for host, want := range map[string]Class{
		"github.com": Propagation, "gitlab.example.com": Propagation, "registry.npmjs.org": Propagation,
		"upload.pypi.org": Propagation, "db.internal": Generic, "evilgithub.com": Generic,
	} {
		ms := extractSecrets([]byte("url = https://x:" + tok + "@" + host + "/o/r.git"))
		if len(ms) != 1 || ms[0].Class != want {
			t.Errorf("%s: %+v, want one %v", host, ms, want)
		}
	}
}
