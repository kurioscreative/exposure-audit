package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const saltSize = 32

// loadSalt reads ~/.exposure-audit/salt, creating it on first run.
func loadSalt(stateDir string) ([]byte, error) {
	p := filepath.Join(stateDir, "salt")
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		b = make([]byte, saltSize)
		rand.Read(b)
		if err := writeExclusive(p, b); err != nil {
			return nil, err
		}
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) != saltSize {
		return nil, errors.New("salt has the wrong size")
	}
	return b, nil
}

// writeExclusive creates p with mode 0600, failing if it exists.
func writeExclusive(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

var errOutputLeak = errors.New("output contains a collected secret")

func isTokenByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		bytes.IndexByte([]byte("_-.+/=:"), c) >= 0
}

// checkLeak splits out on characters outside [A-Za-z0-9_\-.+/=:], HMACs each
// candidate of 8 or more characters, and fails if one matches a collected
// fingerprint (A-26). Candidates are also split on ':', '/' and '=' because
// the set keeps those characters, so a token inside "user:TOKEN" or
// "KEY=TOKEN" would otherwise only be checked as part of the whole run.
func checkLeak(out, salt []byte, fps map[string]bool) error {
	if len(fps) == 0 {
		return nil
	}
	check := func(c []byte) bool { return len(c) >= 8 && fps[fingerprint(salt, c)] }
	for _, cand := range bytes.FieldsFunc(out, func(r rune) bool { return r > 0x7f || !isTokenByte(byte(r)) }) {
		if check(cand) {
			return errOutputLeak
		}
		for _, part := range bytes.FieldsFunc(cand, func(r rune) bool { return r == ':' || r == '/' || r == '=' }) {
			if check(part) {
				return errOutputLeak
			}
		}
	}
	return nil
}
