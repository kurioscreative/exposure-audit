package main

import (
	"math"
	"regexp"
	"slices"
	"strings"
)

// Match is one secret found in text. Name is the variable or key name when
// the text gave one; it is never derived from the value.
type Match struct {
	Value Secret
	Class Class
	Name  string
}

type tokenPattern struct {
	class Class
	rx    *regexp.Regexp
}

// tokenPatterns are known token formats (prototype TOKEN_RX).
var tokenPatterns = []tokenPattern{
	{Propagation, regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{Propagation, regexp.MustCompile(`github_pat_[A-Za-z0-9_]{40,}`)},
	{Propagation, regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	{Propagation, regexp.MustCompile(`pypi-AgEI[A-Za-z0-9_\-]{40,}`)},
	{Propagation, regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{Cloud, regexp.MustCompile(`A[KS]IA[0-9A-Z]{16}`)},
	{Cloud, regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{Cloud, regexp.MustCompile(`dop_v1_[a-f0-9]{64}`)},
	{Service, regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{Service, regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_\-]{32,}`)},
	{Service, regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`)},
	{Service, regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`)},
	{Service, regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`)},
	{Service, regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}`)},
	// The whole key block, so two keys are two credentials; the header alone
	// is the same for every key. A block with no END line (truncated, or a
	// single escaped line cut short) falls back to the header plus body.
	{Service, regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[^-]{0,200})`)},
}

// secretName is a coarse substring prefilter for kvRx. It over-matches
// (author, tokenizer, passwordless); isSecretName decides on word
// boundaries (M3).
const secretName = `(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_\-]?KEY|ACCESS[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH)`

var (
	// secretNameRx is the substring prefilter alone. Use isSecretName for decisions.
	secretNameRx = regexp.MustCompile(`(?i)` + secretName)
	kvRx         = regexp.MustCompile(`(?i)["']?([A-Za-z0-9_.\-]*` + secretName + `[A-Za-z0-9_.\-]*)["']?[ \t]*[:=][ \t]*["']?([^\s"',;}{]{8,})`) // [ \t], not \s: an empty NAME= must not take the next line
	// Short placeholder words must be followed by a non-alphanumeric or the
	// end. As bare prefixes they also rejected random secrets that happen to
	// start with "xxx", "True" or "Null", which made fixture tests flaky.
	placeholderRx = regexp.MustCompile(`(?i)^(?:\$|<|\{\{|%|\*+|changeme|example|placeholder|undefined|password|secret|(?:your|xxx+|todo|none|null|true|false)(?:[^A-Za-z0-9]|$))`)
	// Credentials embedded in URLs (A-20). Group 1: an optional NAME= before
	// the URL; group 2: the password; group 3: the host.
	urlCredRx = regexp.MustCompile(`(?:([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["']?)?[a-z][a-z0-9+.\-]*://[^:/\s@"']+:([^@\s"']+)@([^/\s:"'?#]+)`)
)

// looksReal rejects placeholders and low-variety values (prototype looks_real).
func looksReal(v []byte) bool {
	s := strings.TrimSpace(string(v))
	if len(s) < 8 || placeholderRx.MatchString(s) {
		return false
	}
	distinct := map[rune]bool{}
	for _, r := range s {
		distinct[r] = true
	}
	return len(distinct) >= 5
}

// nameWords splits a key into lowercase words on '_', '-', '.', and camelCase
// boundaries: npmAuthToken → npm auth token, APIKey → api key.
func nameWords(name string) []string {
	var words []string
	var cur []rune
	rs := []rune(name)
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	isUpper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	isLower := func(r rune) bool { return r >= 'a' && r <= 'z' }
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
			continue
		case isUpper(r) && i > 0 && (isLower(rs[i-1]) || rs[i-1] >= '0' && rs[i-1] <= '9'):
			flush() // fooBar, OAuth2Token
		case isUpper(r) && i > 0 && isUpper(rs[i-1]) && i+1 < len(rs) && isLower(rs[i+1]):
			flush() // APIKey
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

// secretWords are whole words that mark a secret. A word may also end in one
// (dbpassword, authtoken, apikey), but "auth" must stand alone so oauth,
// author and authority do not match.
var (
	secretWords    = []string{"token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "credential", "credentials", "auth", "apikey", "accesskey", "privatekey"}
	secretSuffixes = []string{"token", "secret", "password", "passwd", "credential", "credentials", "apikey", "accesskey", "privatekey"}
	secretPairs    = [][2]string{{"api", "key"}, {"access", "key"}, {"private", "key"}}
	// A name ending in one of these describes a secret rather than holding
	// one: TOKEN_EXPIRY, PASSWORD_MIN_LENGTH, AUTH_PROVIDER, SECRET_NAME.
	metadataWords = []string{"url", "uri", "endpoint", "domain", "host", "hostname", "port", "expiry", "expires", "expiration",
		"ttl", "type", "name", "id", "file", "path", "dir", "length", "len", "min", "max", "policy", "provider", "method",
		"mode", "header", "prefix", "enabled", "enable", "version", "timeout", "issuer", "audience", "scope", "scopes",
		"helper", "sock", "socket", "home", "store", "storage", "env", "location", "format", "algorithm", "strategy", "count", "size"}
)

// isSecretName reports whether a key names a secret value, on word
// boundaries (M3): AUTH_TOKEN, _auth, _authToken, apiKey, db_password, but
// not author, OAUTH_CALLBACK, tokenizer, passwordless or TOKEN_EXPIRY.
func isSecretName(name string) bool {
	words := nameWords(name)
	if len(words) == 0 || slices.Contains(metadataWords, words[len(words)-1]) {
		return false
	}
	for i, w := range words {
		if slices.Contains(secretWords, w) {
			return true
		}
		for _, suf := range secretSuffixes {
			if strings.HasSuffix(w, suf) {
				return true
			}
		}
		for _, p := range secretPairs {
			if w == p[0] && i+1 < len(words) && words[i+1] == p[1] {
				return true
			}
		}
	}
	return false
}

// entropyFloor is the minimum Shannon entropy, in bits per character, for a
// value matched by its name only. Known token formats are exempt. Over
// 20,000 draws of random alphanumerics the lowest entropy was 3.50 at 24
// characters, 3.18 at 20 and 2.95 at 16. Dummy values such as hunter2hunter2
// (2.81) and test1234test1234 (2.75) fall under it. In the corpus test 3.0
// is the lowest floor that keeps no false positive; 3.5 is also clean there
// but would drop short random values and passwords like Summer2024! (3.10),
// and 4.0 drops hex and UUID keys. TestEntropyFloorRates prints the rates.
const entropyFloor = 3.0

// entropy is the Shannon entropy of v in bits per byte.
func entropy(v []byte) float64 {
	var counts [256]int
	for _, b := range v {
		counts[b]++
	}
	h := 0.0
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(v))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// wordShaped values are lowercase words joined by separators, with no digits
// or capitals: development, github-oauth, authorization_code. Per-character
// entropy cannot reject them (authorization_code scores 3.57, above an MD5
// hex digest at 3.39), and real generated secrets are almost never shaped so.
// The cost: an all-lowercase passphrase such as correct-horse-battery-staple
// is missed.
func wordShaped(v []byte) bool {
	for _, b := range v {
		if !(b >= 'a' && b <= 'z' || b == '-' || b == '_' || b == '.') {
			return false
		}
	}
	return true
}

// plausibleByName applies the checks for a value matched only by its name
// or its position in a URL: not a placeholder, not a path or URL, above the
// entropy floor, not a plain word.
func plausibleByName(v []byte) bool { return plausibleAt(v, entropyFloor) }

func plausibleAt(v []byte, floor float64) bool {
	return looksReal(v) && !hasAnyPrefix(v, "/", "~", "http://", "https://") &&
		entropy(v) >= floor && !wordShaped(v)
}

// nameOnlySecret is the check for a NAME=value pair whose value matches no
// known token format, such as an environment variable.
func nameOnlySecret(name string, v []byte) bool {
	return isSecretName(name) && plausibleByName(v)
}

// Name rules match whole segments of a name split on '_', '-' and '.', so
// GH_ does not match inside HIGH_WATER_TOKEN (A-17).
var (
	propagationNames = [][]string{{"NPM"}, {"NODE", "AUTH"}, {"GITHUB"}, {"GH"}, {"GITLAB"}, {"PYPI"}, {"TWINE"}, {"CARGO"}, {"RUBYGEMS"}}
	cloudNames       = [][]string{{"AWS"}, {"GOOGLE"}, {"GCP"}, {"GCLOUD"}, {"CLOUDSDK"}, {"AZURE"}, {"ARM"}, {"DIGITALOCEAN"}, {"CLOUDFLARE"}, {"KUBE"}, {"TF"}, {"VAULT"}}
	// Coding-agent session tokens (decision 11): matched as the leading segments only.
	agentPrefixes = [][]string{{"CLAUDE", "CODE"}, {"CLAUDECODE"}, {"CODEX"}, {"CURSOR"}, {"GEMINI", "CLI"}, {"AIDER"}, {"GOOSE"}, {"WINDSURF"}}
)

func nameSegments(name string) []string {
	return strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool { return r == '_' || r == '-' || r == '.' })
}

func containsRun(segs, run []string) bool {
	for i := 0; i+len(run) <= len(segs); i++ {
		if slices.Equal(segs[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

// classForName classes a secret by its variable or key name.
func classForName(name string) Class {
	segs := nameSegments(name)
	for _, run := range propagationNames {
		if containsRun(segs, run) {
			return Propagation
		}
	}
	for _, run := range cloudNames {
		if containsRun(segs, run) {
			return Cloud
		}
	}
	for _, p := range agentPrefixes {
		if len(segs) >= len(p) && slices.Equal(segs[:len(p)], p) {
			return Agent
		}
	}
	return Generic
}

// propagationHosts are registries and forges whose tokens make the victim a
// worm vector. A host matches if it is one of these or a subdomain.
var propagationHosts = []string{"github.com", "githubusercontent.com", "gitlab.com", "npmjs.org", "npmjs.com", "pypi.org"}

func classForURL(host, name string) Class {
	host = strings.ToLower(host)
	first, _, _ := strings.Cut(host, ".")
	if first == "github" || first == "gitlab" { // GitHub Enterprise, self-hosted GitLab
		return Propagation
	}
	for _, h := range propagationHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return Propagation
		}
	}
	if name != "" {
		return classForName(name)
	}
	return Generic
}

// matchSet deduplicates matches by value, keeping the highest class and the
// first name seen.
type matchSet struct {
	byValue map[string]int
	out     []Match
}

func (m *matchSet) add(v []byte, c Class, name string) {
	if m.byValue == nil {
		m.byValue = map[string]int{}
	}
	if i, ok := m.byValue[string(v)]; ok {
		if classRank[c] > classRank[m.out[i].Class] {
			m.out[i].Class = c
		}
		if m.out[i].Name == "" {
			m.out[i].Name = name
		}
		return
	}
	m.byValue[string(v)] = len(m.out)
	m.out = append(m.out, Match{NewSecret(v), c, name})
}

// extractSecrets finds secrets in free text: known token formats, secret-like
// NAME=value pairs, and credentials embedded in URLs.
func extractSecrets(text []byte) []Match {
	var m matchSet
	for _, p := range tokenPatterns {
		for _, v := range p.rx.FindAll(text, -1) {
			m.add(v, p.class, "")
		}
	}
	for _, sm := range kvRx.FindAllSubmatch(text, -1) {
		name, val := sm[1], sm[2]
		if !nameOnlySecret(string(name), val) {
			continue
		}
		m.add(val, classForName(string(name)), string(name))
	}
	// URL passwords are matched by position, not format, so they get the
	// same checks as name-only values: postgres://app:devpass@db is dropped.
	for _, sm := range urlCredRx.FindAllSubmatch(text, -1) {
		if plausibleByName(sm[2]) {
			m.add(sm[2], classForURL(string(sm[3]), string(sm[1])), string(sm[1]))
		}
	}
	return m.out
}

func hasAnyPrefix(v []byte, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(string(v), p) {
			return true
		}
	}
	return false
}

// highestClass is the class of a finding built from several matches.
func highestClass(ms []Match) Class {
	c := Generic
	for _, m := range ms {
		if classRank[m.Class] > classRank[c] {
			c = m.Class
		}
	}
	return c
}

// hits fingerprints matches into a finding's hits.
func (e *Env) hits(ms []Match) []Hit {
	out := make([]Hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, Hit{Fingerprint: e.Fingerprint(m.Value), Class: m.Class, Name: m.Name})
	}
	return out
}
