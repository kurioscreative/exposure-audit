package main

import (
	"encoding/binary"
	"testing"
)

// gitIndex builds an index file of the given version holding paths (sorted,
// as git writes them). Version 3 marks every entry with extended flags.
func gitIndex(ver uint32, paths ...string) []byte {
	b := []byte("DIRC")
	b = binary.BigEndian.AppendUint32(b, ver)
	b = binary.BigEndian.AppendUint32(b, uint32(len(paths)))
	prev := ""
	for _, p := range paths {
		e := make([]byte, 62)
		flags := uint16(min(len(p), 0xfff))
		if ver == 3 {
			flags |= 0x4000
		}
		binary.BigEndian.PutUint16(e[60:], flags)
		if ver == 3 {
			e = append(e, 0, 0)
		}
		if ver == 4 {
			k := 0
			for k < len(prev) && k < len(p) && prev[k] == p[k] {
				k++
			}
			e = append(e, byte(len(prev)-k)) // tests keep this under 128: one varint byte
			e = append(e, p[k:]...)
			e = append(e, 0)
		} else {
			fixed := len(e)
			e = append(e, p...)
			for len(e) < (fixed+len(p)+8)&^7 {
				e = append(e, 0)
			}
		}
		b = append(b, e...)
		prev = p
	}
	return append(b, make([]byte, 20)...) // trailing checksum, not verified
}

func TestParseGitIndexVersions(t *testing.T) {
	paths := []string{".env.development", "config/a.yml", "config/abc.yml", "src/x.go"}
	for _, ver := range []uint32{2, 3, 4} {
		got, err := parseGitIndex(gitIndex(ver, paths...))
		if err != nil {
			t.Fatalf("v%d: %v", ver, err)
		}
		if len(got) != len(paths) {
			t.Errorf("v%d: %d paths, want %d: %v", ver, len(got), len(paths), got)
		}
		for _, p := range paths {
			if !got[p] {
				t.Errorf("v%d: missing %q", ver, p)
			}
		}
	}
}

func TestParseGitIndexRejectsGarbage(t *testing.T) {
	good := gitIndex(2, "a", "b")
	for name, b := range map[string][]byte{
		"empty":     nil,
		"magic":     append([]byte("XXXX"), good[4:]...),
		"version":   append(append([]byte("DIRC"), 0, 0, 0, 9), good[8:]...),
		"truncated": good[:40],
	} {
		if _, err := parseGitIndex(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestGitVarint(t *testing.T) {
	// Git's offset varint: 0x80 0x00 is 128, not 0.
	for _, c := range []struct {
		in   []byte
		want int
	}{{[]byte{0x05}, 5}, {[]byte{0x7f}, 127}, {[]byte{0x80, 0x00}, 128}, {[]byte{0x81, 0x00}, 256}} {
		if got, n := gitVarint(c.in); got != c.want || n != len(c.in) {
			t.Errorf("%x: %d (%d bytes), want %d", c.in, got, n, c.want)
		}
	}
}
