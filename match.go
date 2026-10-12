package main

import (
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
	{Service, regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

const secretName = `(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_\-]?KEY|ACCESS[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH)`

var (
	secretNameRx  = regexp.MustCompile(`(?i)` + secretName)
	kvRx          = regexp.MustCompile(`(?i)["']?([A-Za-z0-9_.\-]*` + secretName + `[A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})`)
	placeholderRx = regexp.MustCompile(`(?i)^(?:\$|<|\{\{|%|your|xxx+|changeme|example|placeholder|todo|none|null|true|false|undefined|password|secret|\*+)`)
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
		if !looksReal(val) || hasAnyPrefix(val, "/", "~", "http://", "https://") {
			continue
		}
		m.add(val, classForName(string(name)), string(name))
	}
	for _, sm := range urlCredRx.FindAllSubmatch(text, -1) {
		if looksReal(sm[2]) {
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
