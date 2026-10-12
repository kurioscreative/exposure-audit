package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// PROVISIONAL (R-07): the parser and classifier are written against the
// hand-written sample in HANDOFF §12 plus assumptions below. Glenn's real
// dump confirmed partition lists and mdat exist but has not been inspected
// structurally. Refit against testdata/ once the sanitized sample is in.
//
// Assumed format, medium confidence:
//   - Attributes: `"svce"<blob>="text"`, `"svce"<blob>=0x<hex>  "text"` for
//     non-ASCII values, `<NULL>` when empty; the label is `0x00000007 <blob>=`.
//   - mdat: `"mdat"<timedate>=0x<hex>  "20250101120000Z\000"`.
//   - Partition list: an access entry whose authorizations are
//     `partition_id`, with the list in `description:`, either as hex of an
//     XML plist holding <string> values or as a comma-separated list.

const keychainKind = "keychain-silent"

var errKeychainDump = errors.New("keychain dump failed")

type kcEntry struct {
	auth []string
	any  bool     // applications: <null>
	apps []string // listed application paths
	desc string
}

type kcItem struct {
	class         string
	attrs         map[string]string
	entries       []*kcEntry
	partitions    []string
	hasPartitions bool
}

var (
	kcAttrRx  = regexp.MustCompile(`^(?:"([^"]{4})"|(0x[0-9A-Fa-f]{8})) ?<\w+>=(.*)$`)
	kcAppRx   = regexp.MustCompile(`^\d+: (.+?)(?: \((?:OK|status:? ?-?\d+)\))?$`)
	kcEntryRx = regexp.MustCompile(`^entry \d+:$`)
	kcPlistRx = regexp.MustCompile(`<string>([^<]*)</string>`)
	kcHexRx   = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2})+$`)
)

// kcAttrValue returns the text of an attribute value: the quoted part when
// present, otherwise the raw token. <NULL> yields "".
func kcAttrValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "<NULL>" {
		return ""
	}
	if i := strings.Index(v, `"`); i >= 0 && strings.HasSuffix(v, `"`) && len(v) > i+1 {
		return v[i+1 : len(v)-1]
	}
	return v
}

func parseKeychainDump(text string) []*kcItem {
	var items []*kcItem
	var cur *kcItem
	var entry *kcEntry
	inApps := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "keychain: ") {
			cur = &kcItem{attrs: map[string]string{}}
			items = append(items, cur)
			entry, inApps = nil, false
			continue
		}
		if cur == nil {
			continue
		}
		s := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(s, "class: ") && cur.class == "" && entry == nil:
			cur.class = strings.Trim(strings.TrimPrefix(s, "class: "), `"`)
		case kcEntryRx.MatchString(s):
			entry, inApps = &kcEntry{}, false
			cur.entries = append(cur.entries, entry)
		case entry == nil:
			if m := kcAttrRx.FindStringSubmatch(s); m != nil {
				tag := m[1]
				if m[2] == "0x00000007" {
					tag = "labl"
				}
				if tag != "" {
					cur.attrs[tag] = kcAttrValue(m[3])
				}
			}
		case strings.HasPrefix(s, "authorizations"):
			if _, words, ok := strings.Cut(s, ":"); ok {
				entry.auth = strings.Fields(words)
			}
			inApps = false
		case strings.HasPrefix(s, "description: "):
			entry.desc = strings.TrimPrefix(s, "description: ")
			inApps = false
		case s == "applications: <null>":
			entry.any = true
			inApps = false
		case strings.HasPrefix(s, "applications ("):
			inApps = true
		case inApps:
			if m := kcAppRx.FindStringSubmatch(s); m != nil {
				entry.apps = append(entry.apps, m[1])
			}
		}
	}
	for _, it := range items {
		it.attrs["mdat"] = strings.TrimSuffix(it.attrs["mdat"], `\000`)
		for _, e := range it.entries {
			if slices.Contains(e.auth, "partition_id") {
				it.hasPartitions = true
				it.partitions = append(it.partitions, parsePartitions(e.desc)...)
			}
		}
	}
	return items
}

// parsePartitions reads a partition_id description: hex of an XML plist, or
// a comma-separated list.
func parsePartitions(desc string) []string {
	if kcHexRx.MatchString(desc) {
		if b, err := hex.DecodeString(desc); err == nil && strings.Contains(string(b), "<string>") {
			var out []string
			for _, m := range kcPlistRx.FindAllStringSubmatch(string(b), -1) {
				out = append(out, strings.TrimSpace(m[1]))
			}
			return out
		}
	}
	var out []string
	for _, p := range strings.Split(desc, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type kcAccess int

const (
	kcUnknown  kcAccess = iota // no decrypt entry, or a tool whose partition cannot be known
	kcAppGated                 // only apps, or tools whose partition is not in the list
	kcSilent
)

type kcVerdict struct {
	access kcAccess
	anyApp bool
	tools  []string // command-line tools a script can call to read the item
}

func isAppPath(p string) bool { return strings.HasSuffix(p, ".app") || strings.Contains(p, ".app/") }

// appleToolDirs hold Apple-signed command-line tools, whose partition is
// apple-tool:. /Library/Developer/CommandLineTools is the Xcode command-line
// tools install; treating it as apple-tool: is an assumption (medium
// confidence) because codesign cannot be run (invariant 8).
var appleToolDirs = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/System/", "/Library/Developer/CommandLineTools/"}

func isAppleTool(p string) bool {
	for _, d := range appleToolDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// classifyKeychainItem applies HANDOFF §12 and the M2 partition rule.
//
// Without a partition list: applications <null> on a decrypt entry means any
// application (silent); a listed path outside an .app bundle means a
// command-line tool can read it (silent via that tool); only .app paths means
// app-gated; no decrypt entry means undetermined.
//
// With a partition list, a tool counts as a silent reader only if its
// partition is in the list. Apple-signed tools are apple-tool:. Any-application
// access is silent only if apple-tool: is listed, because a script can then
// call /usr/bin/security. A non-Apple tool's partition (teamid:, cdhash or
// unsigned) cannot be known without codesign, so an item whose list could
// include it is undetermined rather than guessed.
func classifyKeychainItem(it *kcItem) kcVerdict {
	var dec []*kcEntry
	for _, e := range it.entries {
		if slices.Contains(e.auth, "decrypt") {
			dec = append(dec, e)
		}
	}
	if len(dec) == 0 {
		return kcVerdict{access: kcUnknown}
	}
	anyApp := slices.ContainsFunc(dec, func(e *kcEntry) bool { return e.any })
	var tools []string
	for _, e := range dec {
		for _, a := range e.apps {
			if strings.HasPrefix(a, "/") && !isAppPath(a) && !slices.Contains(tools, a) {
				tools = append(tools, a)
			}
		}
	}
	slices.Sort(tools)
	if !it.hasPartitions {
		switch {
		case anyApp:
			return kcVerdict{access: kcSilent, anyApp: true}
		case len(tools) > 0:
			return kcVerdict{access: kcSilent, tools: tools}
		}
		return kcVerdict{access: kcAppGated}
	}
	appleToolListed := slices.Contains(it.partitions, "apple-tool:")
	if anyApp {
		if appleToolListed {
			return kcVerdict{access: kcSilent, anyApp: true}
		}
		return kcVerdict{access: kcAppGated}
	}
	var ok []string
	undetermined := false
	nonApple := slices.ContainsFunc(it.partitions, func(p string) bool { return p != "apple:" && p != "apple-tool:" })
	for _, t := range tools {
		switch {
		case isAppleTool(t) && appleToolListed:
			ok = append(ok, t)
		case !isAppleTool(t) && nonApple:
			undetermined = true
		}
	}
	switch {
	case len(ok) > 0:
		return kcVerdict{access: kcSilent, tools: ok}
	case undetermined:
		return kcVerdict{access: kcUnknown}
	}
	return kcVerdict{access: kcAppGated}
}

// keychainClass is the prototype heuristic, with cloud words matched on
// whole segments (A-17).
func keychainClass(service, account string) Class {
	name := strings.ToLower(service + " " + account)
	for _, w := range []string{"github", "gh:", "gitlab", "npm", "pypi"} {
		if strings.Contains(name, w) {
			return Propagation
		}
	}
	segs := strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	})
	for _, run := range cloudNames {
		if containsRun(segs, run) {
			return Cloud
		}
	}
	return Service
}

type keychainCollector struct {
	skip  bool
	stats *KeychainStats
}

func newKeychainCollectors(opts Options, _ string) []Collector {
	return []Collector{&keychainCollector{skip: opts.SkipKeychain}}
}

func (*keychainCollector) Name() string { return "keychain" }

func (c *keychainCollector) Section(s *Snapshot) {
	if c.stats != nil {
		s.Keychain = c.stats
	}
}

func loginKeychainPath(env *Env) string {
	return filepath.Join(env.Home, "Library", "Keychains", "login.keychain-db")
}

// dumpKeychain runs `security dump-keychain -a` on the login keychain:
// access lists only, never -d, so no value is read (invariant 7).
func dumpKeychain(ctx context.Context, env *Env) ([]byte, error) {
	out, exit, err := env.Run(ctx, Cmd{Path: "/usr/bin/security", Args: []string{"dump-keychain", "-a", loginKeychainPath(env)}})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || exit != 0 {
		return nil, errKeychainDump
	}
	return out, nil
}

func (c *keychainCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	c.stats = nil
	if c.skip || env.GOOS != "darwin" {
		return nil, ErrSkipped
	}
	if _, err := os.Stat(loginKeychainPath(env)); err != nil {
		return nil, ErrSkipped
	}
	out, err := dumpKeychain(ctx, env)
	if err != nil {
		return nil, err
	}
	helpers := loadHelperConfig(env)
	stats := &KeychainStats{}
	var findings []Finding
	for _, it := range parseKeychainDump(string(out)) {
		if it.class != "genp" && it.class != "inet" {
			continue
		}
		stats.Total++
		v := classifyKeychainItem(it)
		switch v.access {
		case kcUnknown:
			stats.Unknown++
			continue
		case kcAppGated:
			stats.AppGated++
			continue
		}
		stats.Silent++
		f := keychainFinding(env, it, v)
		helpers.enrich(it, v, &f)
		findings = append(findings, f)
	}
	c.stats = stats
	return findings, nil
}

func kcService(it *kcItem) string {
	for _, k := range []string{"svce", "srvr", "labl"} {
		if v := it.attrs[k]; v != "" {
			return v
		}
	}
	return "(unnamed)"
}

// keychainFinding builds a finding whose persisted text holds nothing parsed
// from the dump: no service, account or tool path (decision 16, A-53). Those
// go only to the Live fields. The hit fingerprint adds mdat to the slot key,
// so a changed mdat is a rotation (A-34).
func keychainFinding(env *Env, it *kcItem, v kcVerdict) Finding {
	svc, acct := kcService(it), it.attrs["acct"]
	slot := shortHash(keychainKind, env.FingerprintLabel(kcSlotKey(it)))
	via, liveVia := "any application", "any application"
	if !v.anyApp {
		via, liveVia = "a command-line tool", strings.Join(v.tools, ", ")
	}
	const detail = "Access list trusts %s, so a script can read it by calling that tool. Value was not read by this audit."
	live := "login keychain: " + svc
	if acct != "" {
		live += " (" + acct + ")"
	}
	return Finding{
		SlotID:       slot,
		Layer:        "keychain",
		Kind:         keychainKind,
		Title:        "Keychain item readable without a prompt",
		Location:     "login keychain item " + slot,
		LiveTitle:    "Keychain item readable without a prompt: " + svc,
		LiveLocation: live,
		Lifetime:     Static,
		Gate:         Silent,
		Confidence:   Medium,
		Fix:          fixText["keychain"],
		Detail:       fmt.Sprintf(detail, via),
		LiveDetail:   fmt.Sprintf(detail, liveVia),
		Hits:         []Hit{{Fingerprint: env.FingerprintLabel(kcSlotKey(it) + "|" + it.attrs["mdat"]), Class: keychainClass(svc, acct)}},
	}
}

// kcSlotKey identifies one Keychain item across runs. HANDOFF §5 specifies
// kc|service|account; A-54 widens it with the item class and, for internet
// passwords, protocol, port and path, because items with no name, and inet
// items differing only in those, otherwise share a slot and the diff and
// Fix-first grouping merge unrelated items. mdat stays out: a changed mdat
// must keep the slot so it reads as a rotation.
func kcSlotKey(it *kcItem) string {
	k := "kc|" + it.class + "|" + kcService(it) + "|" + it.attrs["acct"]
	if it.class == "inet" {
		k += "|" + it.attrs["srvr"] + "|" + it.attrs["ptcl"] + "|" + it.attrs["port"] + "|" + it.attrs["path"]
	}
	return k
}
