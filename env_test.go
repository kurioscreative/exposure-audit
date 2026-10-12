package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPlainEnvIsExactlyFiveNames(t *testing.T) {
	want := []string{"__CFBundleIdentifier", "TERM_PROGRAM", "SSH_AUTH_SOCK", "TMUX", "USER"}
	if !slices.Equal(PlainEnv, want) {
		t.Fatalf("PlainEnv = %v, want %v", PlainEnv, want)
	}
}

func TestPlainOnlyReturnsAllowlisted(t *testing.T) {
	env := &Env{Environ: map[string]Secret{
		"TERM_PROGRAM": NewSecret([]byte("ghostty")),
		"API_TOKEN":    NewSecret([]byte(marker("env"))),
	}}
	if got := env.Plain("TERM_PROGRAM"); got != "ghostty" {
		t.Errorf("Plain(TERM_PROGRAM) = %q", got)
	}
	if got := env.Plain("API_TOKEN"); got != "" {
		t.Errorf("Plain returned a non-allowlisted variable")
	}
	if out := fmt.Sprintf("%+v %#v", env, env); strings.Contains(out, marker("env")) {
		t.Errorf("formatting Env leaked an environment value")
	}
}

func TestGuardRunRefusesOtherPrograms(t *testing.T) {
	called := false
	run := guardRun(func(context.Context, Cmd) ([]byte, int, error) { called = true; return nil, 0, nil })
	for _, p := range []string{"/usr/bin/git", "security", "/bin/sh", "/usr/bin/security/../../bin/sh"} {
		if _, _, err := run(context.Background(), Cmd{Path: p}); err == nil {
			t.Errorf("guardRun allowed %q", p)
		}
	}
	if called {
		t.Error("underlying run was called for a refused program")
	}
	for _, p := range AllowedPrograms {
		if _, _, err := run(context.Background(), Cmd{Path: p}); err != nil {
			t.Errorf("guardRun refused allowed %q", p)
		}
	}
}
