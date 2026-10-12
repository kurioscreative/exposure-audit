package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// sanitizeKeychainSample implements -sanitize-keychain-sample: it dumps the
// login keychain's access lists (never values, invariant 7) and prints the
// dump with every name replaced, so Glenn can read it and commit it to
// testdata/ for the classifier (M2, R-07).
//
// Kept: line structure, indentation, the class line, attribute tags and
// types, authorizations, require-password lines, entry and application
// counts, application status suffixes, the partition prefixes apple:,
// apple-tool: and teamid:, application paths inside Apple and developer
// directories, path separators and bundle extensions (so app versus tool
// stays visible), and helper basenames git-credential-osxkeychain and
// docker-credential-* (needed by M4). Timestamps become a fixed valid one.
// Everything else becomes a same-length placeholder.
func (a *App) sanitizeKeychainSample() int {
	if a.Env.GOOS != "darwin" {
		fmt.Fprintln(a.Stderr, "exposure-audit: -sanitize-keychain-sample needs macOS")
		return 2
	}
	out, err := dumpKeychain(context.Background(), a.Env)
	if err != nil {
		fmt.Fprintln(a.Stderr, "exposure-audit: security dump-keychain failed")
		return 2
	}
	a.Stdout.Write([]byte(sanitizeKeychainDump(string(out))))
	return 0
}

var (
	sanKeepRx    = regexp.MustCompile(`^(version: \d+|class: .*|attributes:|access: \d+ entr(y|ies)|entry \d+:|authorizations \(\d+\):[a-z_ ]*|(don't-)?require-password|applications: <null>|applications \(\d+\):)$`)
	sanAppRx     = regexp.MustCompile(`^(\d+: )(.+?)((?: \((?:OK|status:? ?-?\d+)\))?)$`)
	sanAttrValRx = regexp.MustCompile(`^(0x[0-9A-Fa-f]+)?(\s*)(?:"(.*)")?$`)
)

var sanKeepDirs = []string{"/usr/bin/", "/bin/", "/usr/libexec/", "/System/", "/Library/Developer/"}

func placeholder(s string) string { return strings.Repeat("x", len(s)) }

func sanitizeKeychainDump(text string) string {
	lines := strings.Split(text, "\n")
	partitionEntry := false
	for i, line := range lines {
		s := strings.TrimLeft(line, " \t")
		indent := line[:len(line)-len(s)]
		switch {
		case s == "":
		case strings.HasPrefix(s, "keychain: "):
			lines[i] = indent + "keychain: " + placeholderQuoted(strings.TrimPrefix(s, "keychain: "))
		case sanKeepRx.MatchString(s):
			if strings.HasPrefix(s, "entry ") {
				partitionEntry = false
			}
			if strings.HasPrefix(s, "authorizations") && strings.Contains(s, "partition_id") {
				partitionEntry = true
			}
		case kcAttrRx.MatchString(s):
			m := kcAttrRx.FindStringSubmatch(s)
			prefix := s[:len(s)-len(m[3])]
			lines[i] = indent + prefix + sanitizeAttrValue(m[1], m[3])
		case strings.HasPrefix(s, "description: "):
			d := strings.TrimPrefix(s, "description: ")
			if partitionEntry || kcHexRx.MatchString(d) {
				d = sanitizePartitions(d)
			} else {
				d = placeholder(d)
			}
			lines[i] = indent + "description: " + d
		case sanAppRx.MatchString(s):
			m := sanAppRx.FindStringSubmatch(s)
			lines[i] = indent + m[1] + sanitizeAppPath(m[2]) + m[3]
		default:
			lines[i] = indent + placeholder(s)
		}
	}
	return strings.Join(lines, "\n")
}

func placeholderQuoted(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return `"` + placeholder(v[1:len(v)-1]) + `"`
	}
	return placeholder(v)
}

const sanTimestamp = "20000101000000Z"

func sanitizeAttrValue(tag, v string) string {
	if strings.TrimSpace(v) == "<NULL>" {
		return v
	}
	m := sanAttrValRx.FindStringSubmatch(v)
	if m == nil {
		return placeholder(v)
	}
	hexPart, sep, quoted := m[1], m[2], m[3]
	if (tag == "mdat" || tag == "cdat") && strings.HasPrefix(quoted, `20`) && len(quoted) >= len(sanTimestamp) {
		rest := quoted[len(sanTimestamp):] // e.g. \000
		q := sanTimestamp + rest
		h := hexPart
		if h != "" {
			h = "0x" + strings.ToUpper(hex.EncodeToString([]byte(sanTimestamp)))
			h += strings.Repeat("0", max(0, len(hexPart)-len(h)))
			h = h[:len(hexPart)]
		}
		return h + sep + `"` + q + `"`
	}
	out := ""
	if hexPart != "" {
		out = "0x" + strings.Repeat("0", len(hexPart)-2)
	}
	out += sep
	if strings.Contains(v, `"`) {
		out += `"` + placeholder(quoted) + `"`
	}
	return out
}

func sanitizeAppPath(p string) string {
	for _, d := range sanKeepDirs {
		if strings.HasPrefix(p, d) {
			return p
		}
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if seg == "git-credential-osxkeychain" || strings.HasPrefix(seg, "docker-credential-") {
			continue
		}
		ext := ""
		for _, e := range []string{".app", ".appex", ".xpc", ".framework"} {
			if strings.HasSuffix(seg, e) {
				ext = e
			}
		}
		segs[i] = placeholder(strings.TrimSuffix(seg, ext)) + ext
	}
	return strings.Join(segs, "/")
}

// sanitizePartitions keeps the apple:, apple-tool: and teamid: prefixes and
// replaces the rest of each partition value, inside a hex plist or a list.
func sanitizePartitions(d string) string {
	if kcHexRx.MatchString(d) {
		// Only a hex-encoded plist is a partition list. Any other hex text is
		// an ordinary description and must not pass through.
		b, err := hex.DecodeString(d)
		if err != nil || !strings.Contains(string(b), "<plist") {
			return placeholder(d)
		}
		doc := kcPlistRx.ReplaceAllStringFunc(string(b), func(m string) string {
			inner := kcPlistRx.FindStringSubmatch(m)[1]
			return "<string>" + sanitizePartition(inner) + "</string>"
		})
		enc := hex.EncodeToString([]byte(doc))
		if strings.ToUpper(d) == d {
			enc = strings.ToUpper(enc)
		}
		return enc
	}
	parts := strings.Split(d, ",")
	for i, p := range parts {
		lead := p[:len(p)-len(strings.TrimLeft(p, " "))]
		parts[i] = lead + sanitizePartition(strings.TrimLeft(p, " "))
	}
	return strings.Join(parts, ",")
}

func sanitizePartition(p string) string {
	for _, keep := range []string{"apple-tool:", "apple:", "teamid:"} {
		if strings.HasPrefix(p, keep) {
			return keep + placeholder(p[len(keep):])
		}
	}
	return placeholder(p)
}
