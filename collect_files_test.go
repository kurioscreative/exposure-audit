package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func sshStr(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// opensshKey builds an openssh-key-v1 file around a fresh ed25519 key.
// The private section is random bytes: the collector never parses it.
// It returns the file text and the SHA256: fingerprint ssh-add would print.
func (f *fixture) opensshKey(cipher string) (string, string) {
	blob := ed25519Blob(f.t)
	kdf := "none"
	if cipher != "none" {
		kdf = "bcrypt"
	}
	priv := make([]byte, 160)
	rand.Read(priv)
	raw := []byte("openssh-key-v1\x00")
	raw = append(raw, sshStr([]byte(cipher))...)
	raw = append(raw, sshStr([]byte(kdf))...)
	raw = append(raw, sshStr(nil)...)
	raw = binary.BigEndian.AppendUint32(raw, 1)
	raw = append(raw, sshStr(blob)...)
	raw = append(raw, sshStr(priv)...)
	body := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	b.WriteString("-----BEGIN OPENSSH " + "PRIVATE KEY-----\n")
	for len(body) > 70 {
		b.WriteString(body[:70] + "\n")
		f.markers = append(f.markers, body[:70])
		body = body[70:]
	}
	b.WriteString(body + "\n-----END OPENSSH " + "PRIVATE KEY-----\n")
	return b.String(), sshFingerprint(blob)
}

func sshAddStub(fps ...string) func([]string) ([]byte, int) {
	return func([]string) ([]byte, int) {
		if len(fps) == 0 {
			return []byte("The agent has no identities.\n"), 1
		}
		var b strings.Builder
		for _, fp := range fps {
			b.WriteString("256 " + fp + " me@host (ED25519)\n")
		}
		return []byte(b.String()), 0
	}
}

func (f *fixture) fileCollectorsJSON() Snapshot {
	f.t.Helper()
	r := f.runApp(newFileCollectors(Options{}, "unknown"), "-json")
	f.assertNoMarkers(r.stdout, r.stderr)
	r2 := f.runApp(newFileCollectors(Options{}, "unknown"))
	f.assertNoMarkers(r2.stdout, r2.stderr)
	if r.code != 0 {
		f.t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	return decodeSnapshot(f.t, r.stdout)
}

// itemScores maps each item's first location to its score.
func itemScores(s Snapshot) map[string]float64 {
	m := map[string]float64{}
	for _, it := range s.Items {
		m[strings.Join(it.Locations, " + ")] = it.Score
	}
	return m
}

func findingByKind(s Snapshot, kind string) *Finding {
	for i := range s.Findings {
		if s.Findings[i].Kind == kind {
			return &s.Findings[i]
		}
	}
	return nil
}

func TestBaseFixtureFilesAWSSSH(t *testing.T) {
	fx := newFixture(t)
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\nignore-scripts=true\n")
	fx.write(".aws/credentials", "[default]\naws_access_key_id = "+fx.secret("AKIA", 16)+
		"\naws_secret_access_key = "+fx.secret("", 40)+
		"\n\n[tmp]\naws_access_key_id = "+fx.secret("ASIA", 16)+
		"\naws_secret_access_key = "+fx.secret("", 40)+
		"\naws_session_token = "+fx.secret("", 120)+"\n")
	fx.write(".config/gh/hosts.yml", "github.com:\n    user: me\n    oauth_token: "+fx.secret("ghp_", 36)+"\n    git_protocol: https\n")
	plain, _ := fx.opensshKey("none")
	enc, _ := fx.opensshKey("aes256-ctr")
	fx.write(".ssh/id_plain", plain)
	fx.write(".ssh/id_enc", enc)

	s := fx.fileCollectorsJSON()
	want := map[string]float64{
		"~/.npmrc":               10,
		"~/.config/gh/hosts.yml": 10,
		"~/.ssh/id_plain":        10,
		"~/.ssh/id_enc":          1,
	}
	got := itemScores(s)
	for loc, score := range want {
		if got[loc] != score {
			t.Errorf("%s: %v, want %v (items %v)", loc, got[loc], score, got)
		}
	}
	var aws []float64
	for _, it := range s.Items {
		if it.Locations[0] == "~/.aws/credentials" {
			aws = append(aws, it.Score)
		}
	}
	if len(aws) != 2 || aws[0] != 8 || aws[1] != 3.2 {
		t.Errorf("AWS items %v, want static 8.0 then session 3.2 as two items", aws)
	}
	if s.Total != 42.2 || len(s.Credentials) != 6 {
		t.Errorf("total %v with %d credentials, want 42.2 with 6", s.Total, len(s.Credentials))
	}
	if f := findingByKind(s, "aws-session"); f == nil || f.Lifetime != Session {
		t.Errorf("aws session finding %+v", f)
	}
	if f := findingByKind(s, "ssh-key-encrypted"); f == nil || f.Gate != Gated {
		t.Errorf("encrypted key finding %+v", f)
	}
}

func TestSSHKeyInAgentIsOneCredential(t *testing.T) {
	fx := newFixture(t)
	enc, fp := fx.opensshKey("aes256-ctr")
	fx.write(".ssh/id_enc", enc)
	fx.setenv("SSH_AUTH_SOCK", "/tmp/ssh-x/agent.1")
	fx.stubs["/usr/bin/ssh-add"] = sshAddStub(fp)
	s := fx.fileCollectorsJSON()
	if len(s.Credentials) != 1 || s.Total != 10 || s.Credentials[0].Class != Propagation {
		t.Fatalf("credentials %+v total %v; want one propagation 10.0", s.Credentials, s.Total)
	}
	if len(s.Items) != 1 || len(s.Items[0].Locations) != 2 {
		t.Errorf("items %+v; want one listing the file and the agent", s.Items)
	}
	if f := findingByKind(s, "ssh-agent"); f == nil || f.Gate != Silent || f.Location != "SSH agent ($SSH_AUTH_SOCK)" {
		t.Errorf("agent finding %+v", f)
	}
	fx.mu.Lock()
	defer fx.mu.Unlock()
	for _, c := range fx.ran {
		if c.Path == "/usr/bin/ssh-add" && (len(c.Env) != 1 || c.Env[0] != "SSH_AUTH_SOCK=/tmp/ssh-x/agent.1") {
			t.Errorf("ssh-add environment %v", c.Env)
		}
	}
}

func TestOnePasswordAgentIsWindowed(t *testing.T) {
	fx := newFixture(t)
	_, fp := fx.opensshKey("none")
	fx.setenv("SSH_AUTH_SOCK", fx.home+"/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock")
	fx.stubs["/usr/bin/ssh-add"] = sshAddStub(fp)
	s := fx.fileCollectorsJSON()
	if s.Total != 5 {
		t.Errorf("total %v, want 5.0", s.Total)
	}
	if f := findingByKind(s, "ssh-agent"); f == nil || f.Gate != Windowed {
		t.Errorf("agent finding %+v", f)
	}
}

func TestIdentityAgentFromConfig(t *testing.T) {
	fx := newFixture(t)
	_, fp := fx.opensshKey("none")
	fx.write(".ssh/config", "Host *\n  IdentityAgent \"~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh\"\n")
	var sock string
	fx.stubs["/usr/bin/ssh-add"] = sshAddStub(fp)
	s := fx.fileCollectorsJSON()
	f := findingByKind(s, "ssh-agent")
	if f == nil || f.Location != "SSH agent (IdentityAgent in ~/.ssh/config)" || f.Gate != Gated || f.Confidence != Medium {
		t.Fatalf("agent finding %+v", f)
	}
	fx.mu.Lock()
	for _, c := range fx.ran {
		if c.Path == "/usr/bin/ssh-add" {
			sock = c.Env[0]
		}
	}
	fx.mu.Unlock()
	if !strings.HasSuffix(sock, "Secretive.SecretAgent/Data/socket.ssh") || !strings.Contains(sock, fx.home) {
		t.Errorf("socket %q, want the expanded IdentityAgent path", sock)
	}
}

func TestEncryptedKeyWithUseKeychainIsSilent(t *testing.T) {
	fx := newFixture(t)
	enc, _ := fx.opensshKey("aes256-ctr")
	fx.write(".ssh/id_enc", enc)
	fx.write(".ssh/config", "Host *\n  AddKeysToAgent yes\n  UseKeychain yes\n")
	s := fx.fileCollectorsJSON()
	f := findingByKind(s, "ssh-key-encrypted")
	if f == nil || f.Gate != Silent || f.Confidence != Medium || s.Total != 10 {
		t.Errorf("finding %+v total %v; want silent, medium, 10.0", f, s.Total)
	}
}

func TestSSHKeyFingerprintFallbacks(t *testing.T) {
	fx := newFixture(t)
	// A PEM key has no cleartext public half; the .pub next to it decides (A-38).
	blob := ed25519Blob(t)
	pem := "-----BEGIN RSA " + "PRIVATE KEY-----\n" + fx.secret("", 64) + "\n-----END RSA " + "PRIVATE KEY-----\n"
	fx.write(".ssh/id_rsa", pem)
	fx.write(".ssh/id_rsa.pub", "ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob)+" me@host\n")
	fx.write(".ssh/id_other", "-----BEGIN DSA "+"PRIVATE KEY-----\n"+fx.secret("", 64)+"\n-----END DSA "+"PRIVATE KEY-----\n")
	fx.setenv("SSH_AUTH_SOCK", "/tmp/a")
	fx.stubs["/usr/bin/ssh-add"] = sshAddStub(sshFingerprint(blob))
	s := fx.fileCollectorsJSON()
	got := itemScores(s)
	if got["SSH agent ($SSH_AUTH_SOCK) + ~/.ssh/id_rsa"] != 10 {
		t.Errorf("PEM key with .pub did not merge with the agent key: %v", got)
	}
	for _, f := range s.Findings {
		if f.Location == "~/.ssh/id_other" && f.Confidence != Medium {
			t.Errorf("text-fingerprinted key confidence %v, want medium", f.Confidence)
		}
	}
}

// ed25519Blob is a fresh public key in SSH wire format.
func ed25519Blob(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return append(sshStr([]byte("ssh-ed25519")), sshStr(pub)...)
}

func TestSSORefreshTokenIsStatic(t *testing.T) {
	fx := newFixture(t)
	fx.write(".aws/sso/cache/x.json", `{"startUrl":"https://example.awsapps.com/start","accessToken":"`+fx.secret("", 60)+
		`","refreshToken":"`+fx.secret("", 80)+`","expiresAt":"2026-01-01T00:00:00Z"}`)
	fx.write(".aws/sso/cache/y.json", `{"accessToken":"`+fx.secret("", 60)+`","expiresAt":"2026-01-01T00:00:00Z"}`)
	fx.write(".aws/cli/cache/z.json", `{"Credentials":{"SecretAccessKey":"`+fx.secret("", 40)+`","Expiration":"2026-12-01T00:00:00UTC"}}`)
	s := fx.fileCollectorsJSON()
	f := findingByKind(s, "aws-sso-refresh")
	if f == nil || f.Lifetime != Static || f.Confidence != Medium || len(f.Hits) != 1 || f.Hits[0].Class != Cloud {
		t.Fatalf("refresh finding %+v", f)
	}
	live := findingByKind(s, "aws-session")
	if live == nil || len(live.Hits) != 1 {
		t.Errorf("want only the unexpired CLI cache as session: %+v", live)
	}
	if s.Total != 8+3.2 {
		t.Errorf("total %v, want 11.2", s.Total)
	}
}

func TestKnownFileAdditions(t *testing.T) {
	fx := newFixture(t)
	fx.write(".yarnrc.yml", "npmScopes:\n  acme:\n    npmAuthToken: "+fx.secret("npm_", 36)+"\n")
	fx.write(".bundle/config", "---\nBUNDLE_RUBYGEMS__PKG__GITHUB__COM: \"octo:"+fx.secret("ghp_", 36)+"\"\n")
	fx.write(".config/git/credentials", "https://octo:"+fx.secret("ghp_", 36)+"@github.com\n")
	fx.write(".config/glab-cli/config.yml", "hosts:\n  gitlab.com:\n    token: "+fx.secret("glpat-", 20)+"\n")
	fx.write(".config/gcloud/credentials.db", "SQLite format 3")
	fx.write(".npmrc", "registry=https://registry.npmjs.org/\n_authToken=${NPM_TOKEN}\n")
	s := fx.fileCollectorsJSON()
	for kind, want := range map[string]Class{"yarn-token": Propagation, "bundler-token": Propagation, "git-credentials": Propagation, "glab-token": Propagation, "gcloud-db": Cloud} {
		f := findingByKind(s, kind)
		if f == nil || f.Hits[0].Class != want {
			t.Errorf("%s: %+v", kind, f)
		}
	}
	if f := findingByKind(s, "gcloud-db"); f != nil && f.Confidence != Medium {
		t.Errorf("presence-only confidence %v", f.Confidence)
	}
	if findingByKind(s, "npm-token") != nil {
		t.Error("placeholder ${NPM_TOKEN} reported as a token")
	}
	if s.Total != 4*10+8 {
		t.Errorf("total %v, want 48", s.Total)
	}
}
