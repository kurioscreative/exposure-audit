package main

import (
	"encoding/hex"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// keychainFixture is a darwin fixture whose stub security prints dump.
func keychainFixture(t *testing.T, dump *string) *fixture {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Keychains/login.keychain-db", "")
	fx.stubs["/usr/bin/security"] = func(args []string) ([]byte, int) {
		if len(args) != 3 || args[0] != "dump-keychain" || args[1] != "-a" {
			t.Errorf("security called with %v; want dump-keychain -a <path> (invariant 7)", args)
			return nil, 1
		}
		return []byte(*dump), 0
	}
	return fx
}

// keychainNames are the service, account and server names in the samples.
// None may appear in history or -json (decision 16).
var keychainNames = []string{"gh:github.com", "fixture-octo", "fixture-aws", "aws-vault fixture", "bitbucket.org", "fixture-bb",
	"index.docker.io", "fixture-docker", "Fixture Chat", "fixture-tool"}

func assertNoKeychainNames(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, n := range keychainNames {
			if strings.Contains(o, n) {
				t.Errorf("Keychain name %q persisted (decision 16)", n)
			}
		}
	}
}

func TestParseSection12Sample(t *testing.T) {
	items := parseKeychainDump(readTestdata(t, "keychain_section12.txt"))
	if len(items) != 1 {
		t.Fatalf("%d items", len(items))
	}
	it := items[0]
	if it.class != "genp" || it.attrs["svce"] != "gh:github.com" || it.attrs["acct"] != "me" || it.attrs["labl"] != "gh:github.com" {
		t.Errorf("parsed %+v", it)
	}
	v := classifyKeychainItem(it)
	if v.access != kcSilent || !slices.Equal(v.tools, []string{"/usr/bin/security"}) {
		t.Errorf("verdict %+v, want silent via /usr/bin/security", v)
	}
}

func TestClassifyVariants(t *testing.T) {
	items := parseKeychainDump(readTestdata(t, "keychain_variants.txt"))
	want := map[string]kcAccess{
		"gh:github.com":             kcSilent,   // security, apple-tool: partition
		"Fixture Sync":              kcAppGated, // security, but only a teamid partition
		"Fixture Chat Safe Storage": kcAppGated, // app only
		"fixture-encrypt-only":      kcUnknown,  // no decrypt entry
		"aws-vault fixture":         kcSilent,   // any application, no partition list
		"github.com":                kcSilent,   // CLT git-credential-osxkeychain, apple-tool:
		"bitbucket.org":             kcSilent,   // Homebrew git helper, no partition list
		"index.docker.io":           kcSilent,   // docker-credential-desktop, no partition list
		"fixture-tool-item":         kcUnknown,  // non-Apple tool, teamid partition: undetermined
	}
	seen := 0
	for _, it := range items {
		if it.class != "genp" && it.class != "inet" {
			continue
		}
		seen++
		svc := kcService(it)
		if got := classifyKeychainItem(it).access; got != want[svc] {
			t.Errorf("%s: access %v, want %v", svc, got, want[svc])
		}
	}
	if seen != len(want) {
		t.Errorf("%d password items, want %d", seen, len(want))
	}
	if items[0].attrs["mdat"] != "20250301120000Z" || !slices.Equal(items[0].partitions, []string{"apple-tool:", "apple:"}) {
		t.Errorf("mdat %q partitions %v", items[0].attrs["mdat"], items[0].partitions)
	}
}

func TestKeychainCollectorFindingsAndPrivacy(t *testing.T) {
	dump := readTestdata(t, "keychain_variants.txt")
	fx := keychainFixture(t, &dump)
	cs := newKeychainCollectors(Options{}, "unknown")
	s, code := fx.runJSON(cs)
	if code != 0 || s.Collectors["keychain"] != Complete {
		t.Fatalf("exit %d status %v", code, s.Collectors["keychain"])
	}
	if s.Keychain == nil || *s.Keychain != (KeychainStats{Total: 9, Silent: 5, AppGated: 2, Unknown: 2}) {
		t.Errorf("stats %+v", s.Keychain)
	}
	// Plain classes: gh propagation, aws cloud, github propagation, bitbucket service, docker service.
	if s.Total != 38 || len(s.Findings) != 5 {
		t.Errorf("total %v with %d findings, want 38 with 5", s.Total, len(s.Findings))
	}
	for _, f := range s.Findings {
		if f.Location != "login keychain item "+f.SlotID || f.Confidence != Medium || f.Gate != Silent {
			t.Errorf("finding %+v", f)
		}
	}
	r := fx.runApp(cs)
	if !strings.Contains(r.stdout, "gh:github.com") {
		t.Errorf("live summary should name the item:\n%s", r.stdout)
	}
	h := fx.historyFiles()
	assertNoKeychainNames(t, append(h, fx.runApp(cs, "-json").stdout)...)
	fx.assertNoMarkers(r.stdout, r.stderr)
}

func hexEncode(s string) string { return hex.EncodeToString([]byte(s)) }

var hexRunRx = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}){16,}`)

// decodeHexRuns decodes every long hex run, so markers hidden in a hex
// partition plist are visible to the leak check.
func decodeHexRuns(s string) string {
	var b strings.Builder
	for _, run := range hexRunRx.FindAllString(s, -1) {
		if d, err := hex.DecodeString(run); err == nil {
			b.Write(d)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func TestKeychainChangedMdatIsRotated(t *testing.T) {
	dump := readTestdata(t, "keychain_section12.txt")
	dump = strings.Replace(dump, `    "svce"`, "    \"mdat\"<timedate>=0x00  \"20250101120000Z\\000\"\n    \"svce\"", 1)
	fx := keychainFixture(t, &dump)
	cs := newKeychainCollectors(Options{}, "unknown")
	first, _ := fx.runJSON(cs)
	dump = strings.Replace(dump, "20250101120000Z", "20250601120000Z", 1)
	second, _ := fx.runJSON(cs)
	if first.Findings[0].SlotID != second.Findings[0].SlotID || first.Findings[0].ID == second.Findings[0].ID {
		t.Fatalf("mdat change: slot %s→%s id %s→%s", first.Findings[0].SlotID, second.Findings[0].SlotID, first.Findings[0].ID, second.Findings[0].ID)
	}
	if len(second.Diff.Changes) != 1 || second.Diff.Changes[0].State != Rotated || second.Diff.Delta != 0 {
		t.Errorf("diff %+v, want one rotated, delta 0 (A-34)", second.Diff)
	}
}

func TestKeychainSkipped(t *testing.T) {
	dump := readTestdata(t, "keychain_section12.txt")
	fx := keychainFixture(t, &dump)
	s, code := fx.runJSON(newKeychainCollectors(Options{SkipKeychain: true}, "unknown"))
	if code != 0 || s.Collectors["keychain"] != Skipped {
		t.Errorf("-skip-keychain: exit %d status %v", code, s.Collectors["keychain"])
	}
	fx.goos = "linux"
	s, code = fx.runJSON(newKeychainCollectors(Options{}, "unknown"))
	if code != 0 || s.Collectors["keychain"] != Skipped {
		t.Errorf("linux: exit %d status %v", code, s.Collectors["keychain"])
	}
	fx.mu.Lock()
	defer fx.mu.Unlock()
	for _, c := range fx.ran {
		if c.Path == "/usr/bin/security" {
			t.Errorf("security ran while skipped: %v", c)
		}
	}
}

func TestKeychainDumpFailureIsFailed(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Keychains/login.keychain-db", "")
	fx.stubs["/usr/bin/security"] = func([]string) ([]byte, int) { return nil, 51 }
	s, code := fx.runJSON(newKeychainCollectors(Options{}, "unknown"))
	if code != 1 || s.Collectors["keychain"] != Failed {
		t.Errorf("exit %d status %v", code, s.Collectors["keychain"])
	}
}

func helperFixture(t *testing.T, dump *string) *fixture {
	fx := keychainFixture(t, dump)
	fx.write(".gitconfig", "[user]\n\tname = fixture\n[credential]\n\thelper = osxkeychain\n")
	fx.write(".config/gh/hosts.yml", "github.com:\n    user: fixture\n    git_protocol: https\n")
	fx.write(".docker/config.json", `{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"desktop"}`)
	return fx
}

func TestHelperInferenceEnrichesKeychainFindings(t *testing.T) {
	dump := readTestdata(t, "keychain_variants.txt")
	plain := keychainFixture(t, &dump)
	ps, _ := plain.runJSON(newKeychainCollectors(Options{}, "unknown"))

	fx := helperFixture(t, &dump)
	cs := newKeychainCollectors(Options{}, "unknown")
	s, code := fx.runJSON(cs)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(s.Findings) != len(ps.Findings) {
		t.Errorf("%d findings, want %d: M4 must not add findings", len(s.Findings), len(ps.Findings))
	}
	titles := map[string]Class{}
	for _, f := range s.Findings {
		titles[f.Title] = f.Hits[0].Class
	}
	for title, class := range map[string]Class{
		"GitHub CLI token, readable by any process through /usr/bin/security":                       Propagation,
		"Git credentials in the Keychain, usable by any process through git-credential-osxkeychain": Propagation,
		"Docker registry credentials, usable by any process through docker-credential-desktop":      Service,
		"Keychain item readable without a prompt":                                                   Cloud,
	} {
		if c, ok := titles[title]; !ok || c != class {
			t.Errorf("title %q: class %v present %v; want %v", title, c, ok, class)
		}
	}
	// Only the Bitbucket item changes class (service → propagation, HANDOFF
	// M4), so the total rises by exactly 5. Everything else is unchanged.
	if s.Total != ps.Total+5 {
		t.Errorf("total %v, plain %v; want plain + 5 (Bitbucket class only)", s.Total, ps.Total)
	}
	r := fx.runApp(cs)
	for _, want := range []string{"Git credentials for github.com", "Git credentials for bitbucket.org", "Docker registry credentials for index.docker.io"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("live summary lacks %q:\n%s", want, r.stdout)
		}
	}
	assertNoKeychainNames(t, append(fx.historyFiles(), fx.runApp(cs, "-json").stdout)...)
	fx.mu.Lock()
	defer fx.mu.Unlock()
	for _, c := range fx.ran {
		if c.Path != "/usr/bin/security" && c.Path != "/bin/ps" {
			t.Errorf("ran %s: no helper may be executed (decision 14)", c.Path)
		}
		if slices.Contains(c.Args, "-d") {
			t.Error("dump-keychain called with -d (invariant 7)")
		}
	}
}

func TestHelperTotalUnchangedWhenClassesAgree(t *testing.T) {
	// HANDOFF M4 acceptance: no change to the total against the plain Keychain
	// findings, checked on items whose plain class already matches M4's.
	full := readTestdata(t, "keychain_variants.txt")
	var keep []string
	for _, chunk := range strings.SplitAfter(full, "\nkeychain: ") {
		if !strings.Contains(chunk, "bitbucket.org") {
			keep = append(keep, chunk)
		}
	}
	dump := strings.Join(keep, "")
	if strings.Contains(dump, "bitbucket") || !strings.Contains(dump, "Docker Credentials") {
		t.Fatal("bad split")
	}
	plain := keychainFixture(t, &dump)
	ps, _ := plain.runJSON(newKeychainCollectors(Options{}, "unknown"))
	fx := helperFixture(t, &dump)
	s, _ := fx.runJSON(newKeychainCollectors(Options{}, "unknown"))
	if s.Total != ps.Total || len(s.Findings) != len(ps.Findings) {
		t.Errorf("enriched total %v (%d findings), plain %v (%d)", s.Total, len(s.Findings), ps.Total, len(ps.Findings))
	}
}

func TestGitHelperConfigParse(t *testing.T) {
	cases := map[string]bool{
		"[credential]\n\thelper = osxkeychain\n":                             true,
		"[credential \"https://github.com\"]\n  helper = osxkeychain\n":      true,
		"[credential]\nhelper = /usr/local/bin/git-credential-osxkeychain\n": true,
		"[credential]\n\thelper = store\n":                                   false,
		"[alias]\n\thelper = osxkeychain\n":                                  false,
		"[credential]\n\thelper = manager\n[core]\n\thelper = osxkeychain\n": false,
	}
	for in, want := range cases {
		if got := gitHelperIsOSXKeychain(in); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestSanitizeKeychainSample(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	m := []string{fx.secret("", 12), fx.secret("", 12), fx.secret("", 12), fx.secret("", 10), fx.secret("", 10), fx.secret("TEAM", 6)}
	dump := strings.NewReplacer(
		"gh:github.com", "svc-"+m[0],
		"fixture-octo", "acct-"+m[1],
		"Fixture Chat", m[2],
		"/Users/fixture", "/Users/"+m[3],
		"fixture-tool", "tool-"+m[4],
		"FIXTURE02", m[5],
	).Replace(readTestdata(t, "keychain_variants.txt"))
	// Partition plists are hex: rebuild the teamid one with a marker inside.
	dump = strings.Replace(dump, hexUpper("teamid:FIXTURE01"), hexUpper("teamid:"+m[5]), 1)
	fx.stubs["/usr/bin/security"] = func([]string) ([]byte, int) { return []byte(dump), 0 }

	r := fx.runApp(nil, "-sanitize-keychain-sample")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	fx.assertNoMarkers(r.stdout, r.stderr, decodeHexRuns(r.stdout))
	out := r.stdout
	if strings.Count(out, "\n") != strings.Count(dump, "\n") {
		t.Error("line count changed")
	}
	for _, keep := range []string{`class: "genp"`, `class: "inet"`, "class: 0x80001000", `"svce"<blob>="`, `"acct"<blob>=`, "0x00000007 <blob>=",
		"authorizations (6): decrypt derive export_clear export_wrapped mac sign", "authorizations (1): partition_id",
		"don't-require-password", "applications: <null>", "applications (1):", "0: /usr/bin/security (OK)",
		"/Library/Developer/CommandLineTools/usr/libexec/git-core/git-credential-osxkeychain", "/docker-credential-desktop (OK)",
		".app/", `"mdat"<timedate>=0x`, `"20000101000000Z\000"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("sanitized output lost %q", keep)
		}
	}
	for _, p := range []string{"apple-tool:", "apple:", "teamid:"} {
		if !strings.Contains(decodeHexRuns(out), "<string>"+p) {
			t.Errorf("partition prefix %s lost", p)
		}
	}
	// The sanitized sample still parses into the same shape.
	got, want := parseKeychainDump(out), parseKeychainDump(dump)
	if len(got) != len(want) {
		t.Fatalf("%d items after sanitizing, want %d", len(got), len(want))
	}
	for i := range got {
		if a, b := classifyKeychainItem(got[i]).access, classifyKeychainItem(want[i]).access; a != b {
			t.Errorf("item %d classifies %v after sanitizing, %v before", i, a, b)
		}
	}
	assertNoKeychainNames(t, out)
	if fx.runApp(nil, "-sanitize-keychain-sample").code != 0 {
		t.Error("second run failed")
	}
	fx.goos = "linux"
	if r := fx.runApp(nil, "-sanitize-keychain-sample"); r.code != 2 {
		t.Errorf("linux: exit %d, want 2", r.code)
	}
}

func hexUpper(s string) string { return strings.ToUpper(hexEncode(s)) }
