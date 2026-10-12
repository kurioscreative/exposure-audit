package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Built at runtime so no literal resembling a token is committed (HANDOFF §4).
func marker(tag string) string { return "LEAKMARK" + "-" + tag + "-" + "q7Zp" }

func TestSecretNeverFormatsItsValue(t *testing.T) {
	val := marker("secret")
	s := NewSecret([]byte(val))
	type wrapped struct {
		name string
		s    Secret // unexported field: fmt prints these raw (A-02)
	}
	type exported struct{ S Secret }
	cases := map[string]any{
		"bare":       s,
		"pointer":    &s,
		"unexported": wrapped{"x", s},
		"exported":   exported{s},
		"slice":      []Secret{s, s},
		"map":        map[string]Secret{"k": s},
		"nested":     map[string][]wrapped{"k": {{"y", s}}},
	}
	for name, v := range cases {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, val) || strings.Contains(out, fmt.Sprintf("%x", val)) {
				t.Errorf("%s with %s leaked: %s", name, verb, out)
			}
		}
		if out, err := json.Marshal(v); err == nil && strings.Contains(string(out), val) {
			t.Errorf("%s: json.Marshal leaked: %s", name, out)
		}
	}
}

func TestSecretFingerprint(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	a := NewSecret([]byte(marker("a"))).Fingerprint(salt)
	if len(a) != 12 {
		t.Fatalf("fingerprint length %d, want 12", len(a))
	}
	if a != NewSecret([]byte(marker("a"))).Fingerprint(salt) {
		t.Error("fingerprint not stable")
	}
	if a == NewSecret([]byte(marker("b"))).Fingerprint(salt) {
		t.Error("different values share a fingerprint")
	}
	if a == NewSecret([]byte(marker("a"))).Fingerprint([]byte("other salt")) {
		t.Error("fingerprint ignores the salt")
	}
}

func TestNewSecretCopies(t *testing.T) {
	buf := []byte(marker("copy"))
	s := NewSecret(buf)
	salt := []byte("s")
	before := s.Fingerprint(salt)
	buf[0] = 'X'
	if s.Fingerprint(salt) != before {
		t.Error("NewSecret aliases the caller's buffer")
	}
}
