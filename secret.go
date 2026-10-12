package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Secret holds a raw credential value. The only way out is Fingerprint.
//
// The pointer is deliberate. fmt does not call String or Format on unexported
// struct fields; it prints them raw. A []byte field leaks the value under %s
// (verified with Go 1.26). A pointer field prints as an address. (A-02)
type Secret struct{ p *[]byte }

// NewSecret copies b so the caller's buffer can be reused or dropped.
func NewSecret(b []byte) Secret {
	c := append([]byte(nil), b...)
	return Secret{p: &c}
}

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "[redacted]" }
func (Secret) Format(f fmt.State, _ rune)   { io.WriteString(f, "[redacted]") }
func (Secret) MarshalJSON() ([]byte, error) { return nil, errors.New("secret is not serializable") }
func (Secret) MarshalText() ([]byte, error) { return nil, errors.New("secret is not serializable") }

// Fingerprint is hex(HMAC-SHA256(salt, value))[:12].
func (s Secret) Fingerprint(salt []byte) string {
	return fingerprint(salt, s.bytes())
}

// IsZero reports whether the secret holds no value.
func (s Secret) IsZero() bool { return s.p == nil || len(*s.p) == 0 }

// bytes is package-internal: matchers need to inspect values (prefixes,
// entropy), but nothing outside the matcher should call it.
func (s Secret) bytes() []byte {
	if s.p == nil {
		return nil
	}
	return *s.p
}

func fingerprint(salt, value []byte) string {
	m := hmac.New(sha256.New, salt)
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil))[:12]
}
