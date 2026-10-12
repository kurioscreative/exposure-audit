package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type sshCollector struct{}

func (sshCollector) Name() string { return "ssh" }

func (sshCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	cfg := readSSHConfig(env)
	var out []Finding
	inAgent := map[string]bool{}
	for _, a := range sshAgents(env, cfg) {
		if ctx.Err() != nil {
			return out, ErrPartial
		}
		f, keys := agentFinding(ctx, env, a)
		if f == nil {
			continue
		}
		for _, k := range keys {
			inAgent[k] = true
		}
		out = append(out, *f)
	}
	out = append(out, sshKeyFiles(env, cfg, inAgent)...)
	return out, nil
}

// sshConfig is what the collector needs from ~/.ssh/config.
type sshConfig struct {
	identityAgents []string // socket paths, ~ and %d expanded
	useKeychain    bool
}

// A quoted value may contain spaces: 1Password's documented socket lives in
// "~/Library/Group Containers/...". Group 2 is quoted, group 3 bare.
var sshOptionRx = regexp.MustCompile(`(?im)^[ \t]*(IdentityAgent|UseKeychain)(?:[ \t]*=[ \t]*|[ \t]+)(?:"([^"\n]+)"|([^"\s]+))`)

// readSSHConfig reads IdentityAgent (A-22) and UseKeychain from every
// section. Host blocks are not evaluated: any agent the config can point at
// is one a script could use.
func readSSHConfig(env *Env) sshConfig {
	var c sshConfig
	text, err := env.readFile(filepath.Join(env.Home, ".ssh", "config"), defaultReadLimit)
	if err != nil {
		return c
	}
	for _, m := range sshOptionRx.FindAllSubmatch(text, -1) {
		key, val := strings.ToLower(string(m[1])), string(m[2])+string(m[3])
		if key == "usekeychain" {
			c.useKeychain = c.useKeychain || strings.EqualFold(val, "yes")
			continue
		}
		switch {
		case strings.EqualFold(val, "none"):
			continue
		case val == "SSH_AUTH_SOCK" || val == "$SSH_AUTH_SOCK":
			continue // the environment's agent, checked anyway
		case strings.HasPrefix(val, "~/"):
			val = filepath.Join(env.Home, val[2:])
		case strings.HasPrefix(val, "%d/"):
			val = filepath.Join(env.Home, val[3:])
		}
		if !filepath.IsAbs(val) || strings.ContainsAny(val, "%$") {
			continue // other ssh tokens are not expanded
		}
		c.identityAgents = append(c.identityAgents, val)
	}
	return c
}

type sshAgent struct {
	sock  string
	label string // fixed text: the Location never carries the socket path (A-26)
}

func sshAgents(env *Env, cfg sshConfig) []sshAgent {
	var agents []sshAgent
	seen := map[string]bool{}
	if s := env.Plain("SSH_AUTH_SOCK"); s != "" {
		agents = append(agents, sshAgent{s, "SSH agent ($SSH_AUTH_SOCK)"})
		seen[s] = true
	}
	n := 0
	for _, s := range cfg.identityAgents {
		if seen[s] {
			continue
		}
		seen[s] = true
		n++
		label := "SSH agent (IdentityAgent in ~/.ssh/config)"
		if n > 1 {
			label = "SSH agent (IdentityAgent " + strconv.Itoa(n) + " in ~/.ssh/config)"
		}
		agents = append(agents, sshAgent{s, label})
	}
	return agents
}

var approvalAgentRx = regexp.MustCompile(`(?i)secretive|yubikey`)

// agentFinding lists the keys an agent holds with ssh-add -l, which prints
// public fingerprints only. It returns the fingerprint strings it saw.
func agentFinding(ctx context.Context, env *Env, a sshAgent) (*Finding, []string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, exit, err := env.Run(ctx, Cmd{Path: "/usr/bin/ssh-add", Args: []string{"-l"}, Env: []string{"SSH_AUTH_SOCK=" + a.sock}})
	if err != nil || exit != 0 {
		return nil, nil // exit 1: no identities; 2: no agent at that socket
	}
	var keys []string
	var hits []Hit
	for _, line := range strings.Split(string(out), "\n") {
		fs := strings.Fields(line)
		if len(fs) >= 2 && strings.HasPrefix(fs[1], "SHA256:") {
			keys = append(keys, fs[1])
			hits = append(hits, Hit{Fingerprint: env.FingerprintLabel(fs[1]), Class: Propagation})
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	f := &Finding{
		Layer: "ambient", Kind: "ssh-agent", Title: "Keys usable through the SSH agent", Location: a.label,
		Fix: fixText["ssh-agent"], Hits: hits,
		Detail: "Any process can ask the agent to sign with these keys. Nothing needs to be read from disk.",
	}
	switch {
	case strings.Contains(strings.ToLower(a.sock), "1password"):
		// Decision 10: 1Password asks once, then lets the same app use the key
		// for a while. Unverified on Glenn's Mac which window applies to a
		// child process of an approved terminal (medium confidence).
		f.Gate = Windowed
		f.Detail = "This is the 1Password SSH agent. It asks for approval, then allows further use for a while without asking."
	case approvalAgentRx.MatchString(a.sock):
		f.Gate, f.Confidence = Gated, Medium
		f.Detail = "The socket name suggests an agent that asks for approval per use (Secretive or a YubiKey); verify its settings."
	}
	return f, keys
}

// sshKeyFiles reports private keys in ~/.ssh. Keys are fingerprinted by
// public key, the same SHA256: string ssh-add -l prints, so a key file and
// the same key in an agent are one credential and adding a passphrase is
// not a rotation (A-15).
func sshKeyFiles(env *Env, cfg sshConfig, inAgent map[string]bool) []Finding {
	dir := filepath.Join(env.Home, ".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 20000 {
			continue
		}
		text, err := env.readFile(p, 20000)
		if err != nil || !bytes.Contains(text, []byte("PRIVATE KEY-----")) {
			continue
		}
		pub, enc := parseOpenSSHKey(text)
		if pub == nil {
			pub = readPubFile(env, p+".pub")
		}
		f := Finding{Layer: "files", Location: env.tilde(p), Notes: env.fileNotes(p, Static)}
		if pub != nil {
			f.Hits = []Hit{{Fingerprint: env.FingerprintLabel(sshFingerprint(pub)), Class: Propagation}}
		} else {
			// No public half available (A-38): fingerprint the file text.
			f.Hits = []Hit{{Fingerprint: env.Fingerprint(NewSecret(text)), Class: Propagation}}
			f.Confidence = Medium
		}
		key := ""
		if pub != nil {
			key = sshFingerprint(pub)
		}
		switch {
		case enc == encYes && inAgent[key]:
			f.Kind, f.Title, f.Gate, f.Fix = "ssh-key-encrypted", "SSH private key (passphrase protected)", Gated, fixText["ssh-agent"]
			f.Detail = "The file needs the passphrase, but the same key is loaded in an SSH agent; see the agent location."
		case enc == encYes && cfg.useKeychain:
			// Unverified on macOS (medium confidence): with UseKeychain yes,
			// ssh takes the passphrase from the login keychain without asking.
			f.Kind, f.Title, f.Fix = "ssh-key-encrypted", "SSH private key with its passphrase in the Keychain", fixText["ssh-plain"]
			f.Confidence = Medium
			f.Detail = "~/.ssh/config sets UseKeychain yes, so ssh can unlock this key without a prompt."
		case enc == encYes:
			f.Kind, f.Title, f.Gate, f.Fix = "ssh-key-encrypted", "SSH private key (passphrase protected)", Gated, fixText["ssh-agent"]
			f.Detail = "File is stealable but needs the passphrase."
		default:
			f.Kind, f.Title, f.Fix = "ssh-key-plain", "SSH private key with no passphrase", fixText["ssh-plain"]
			if enc == encUnknown {
				f.Confidence = Medium
			}
		}
		out = append(out, f)
	}
	return out
}

type encState int

const (
	encUnknown encState = iota
	encNo
	encYes
)

// parseOpenSSHKey returns the cleartext public key blob of an
// openssh-key-v1 file (present even when the private half is encrypted) and
// whether it is encrypted. PEM keys return no blob; "ENCRYPTED" in the
// header marks them encrypted, as in the prototype.
func parseOpenSSHKey(text []byte) ([]byte, encState) {
	s := string(text)
	if !strings.Contains(s, "BEGIN OPENSSH PRIVATE KEY") {
		if strings.Contains(s, "ENCRYPTED") {
			return nil, encYes
		}
		return nil, encNo
	}
	var body strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "-----") {
			body.WriteString(l)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(body.String(), "="))
		if err != nil {
			return nil, encUnknown
		}
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, encUnknown
	}
	r := raw[len(magic):]
	cipher, r, ok := sshString(r)
	if !ok {
		return nil, encUnknown
	}
	enc := encNo
	if string(cipher) != "none" {
		enc = encYes
	}
	if _, r, ok = sshString(r); !ok { // kdfname
		return nil, enc
	}
	if _, r, ok = sshString(r); !ok { // kdfoptions
		return nil, enc
	}
	if len(r) < 4 || binary.BigEndian.Uint32(r) < 1 {
		return nil, enc
	}
	pub, _, ok := sshString(r[4:])
	if !ok {
		return nil, enc
	}
	return pub, enc
}

func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// readPubFile returns the key blob from an authorized_keys-style .pub file.
func readPubFile(env *Env, p string) []byte {
	b, err := env.readFile(p, 20000)
	if err != nil {
		return nil
	}
	fs := strings.Fields(string(b))
	if len(fs) < 2 {
		return nil
	}
	blob, err := base64.StdEncoding.DecodeString(fs[1])
	if err != nil {
		return nil
	}
	return blob
}

// sshFingerprint is what ssh-add -l prints: SHA256: and unpadded base64 of
// sha256(blob).
func sshFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
