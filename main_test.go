package main

import (
	"strings"
	"testing"
)

// -h is a request, not a mistake: it exits 0 and says what the tool is for.
// The developer-only flag stays out of the help but keeps working.
func TestHelpAndVersion(t *testing.T) {
	fx := newFixture(t)
	r := fx.runApp([]Collector{}, "-h")
	if r.code != 0 || !strings.Contains(r.stderr, "install script") || !strings.Contains(r.stderr, "-skip-keychain") {
		t.Errorf("-h: exit %d, usage %q", r.code, r.stderr)
	}
	if strings.Contains(r.stderr, "sanitize") {
		t.Error("-h lists the developer-only flag")
	}
	if r := fx.runApp([]Collector{}, "-version"); r.code != 0 || r.stdout != "exposure-audit "+version+"\n" {
		t.Errorf("-version: exit %d, %q", r.code, r.stdout)
	}
	for _, bad := range [][]string{{"-nope"}, {"extra"}} {
		if r := fx.runApp([]Collector{}, bad...); r.code != 2 {
			t.Errorf("%q: exit %d, want 2", bad, r.code)
		}
	}
	if len(fx.historyFiles()) != 0 {
		t.Error("-h or -version wrote history")
	}
}
