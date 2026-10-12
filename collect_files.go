package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// fileSpec is one known credential file (prototype SPECS). A nil rx means
// presence only: the store is not parsed.
type fileSpec struct {
	kind, title string
	rels        []string
	class       Class
	rx          *regexp.Regexp // group 1 captures the secret
	fix         string
}

func spec(kind, title string, rels []string, class Class, rx, fix string) fileSpec {
	var re *regexp.Regexp
	if rx != "" {
		re = regexp.MustCompile(rx)
	}
	return fileSpec{kind, title, rels, class, re, fix}
}

var fileSpecs = []fileSpec{
	spec("npm-token", "npm auth token", []string{".npmrc"}, Propagation,
		`(?im)^\s*(?://[^\s=]+:)?(?:_authToken|_auth|_password)\s*=\s*"?([^\s"]+)`, "npm"),
	// Yarn Berry (A-21). Also matches entries nested under npmScopes or npmRegistries.
	spec("yarn-token", "Yarn npm auth token", []string{".yarnrc.yml"}, Propagation,
		`(?im)^\s*npmAuthToken:\s*["']?([^\s"']+)`, "npm"),
	spec("pypi-token", "PyPI upload credential", []string{".pypirc"}, Propagation,
		`(?im)^\s*password\s*[=:]\s*(\S+)`, "registry"),
	spec("cargo-token", "crates.io token", []string{".cargo/credentials.toml", ".cargo/credentials"}, Propagation,
		`(?im)^\s*token\s*=\s*"([^"]+)"`, "registry"),
	spec("gem-token", "RubyGems API key", []string{".gem/credentials"}, Propagation,
		`(?im)^\s*:\w+:\s*(\S+)`, "registry"),
	// Bundler stores BUNDLE_<HOST>: "user:token"; only the token part is the secret (A-21).
	spec("bundler-token", "Bundler gem source credentials", []string{".bundle/config"}, Propagation,
		`(?m)^\s*BUNDLE_[A-Z0-9_]+:\s*["']?[^:\s"']+:([^\s"']+)`, "registry"),
	spec("gh-token", "GitHub CLI token in plaintext", []string{".config/gh/hosts.yml"}, Propagation,
		`(?im)^\s*oauth_token:\s*(\S+)`, "github"),
	// git's XDG credential store has the same format as ~/.git-credentials (A-21).
	spec("git-credentials", "Git credential store (plaintext)", []string{".git-credentials", ".config/git/credentials"}, Propagation,
		`(?m)^https?://[^:\s/]+:([^@\s]+)@`, "github"),
	spec("glab-token", "GitLab CLI token in plaintext", []string{".config/glab-cli/config.yml"}, Propagation,
		`(?m)^\s*token:\s*["']?([^\s"']+)`, "github"),
	spec("netrc", "netrc passwords", []string{".netrc"}, Service, `(?i)password\s+(\S+)`, "file-token"),
	spec("gcloud-adc", "Google Cloud application default credentials",
		[]string{".config/gcloud/application_default_credentials.json"}, Cloud,
		`"(?:refresh_token|private_key)"\s*:\s*"([^"]+)"`, "cloud"),
	spec("gcloud-db", "Google Cloud CLI credential database",
		[]string{".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db"}, Cloud, "", "cloud"),
	spec("azure-cache", "Azure CLI token cache",
		[]string{".azure/msal_token_cache.json", ".azure/accessTokens.json", ".azure/service_principal_entries.json"},
		Cloud, "", "cloud"),
	spec("kube", "Kubernetes embedded credentials", []string{".kube/config"}, Cloud,
		`(?m)^\s*(?:token|client-key-data|password):\s*(\S+)`, "kube"),
	spec("docker-auth", "Docker registry auth stored inline", []string{".docker/config.json"}, Service,
		`"auth"\s*:\s*"([^"]+)"`, "docker"),
	spec("terraform", "Terraform Cloud token", []string{".terraform.d/credentials.tfrc.json", ".terraformrc"}, Cloud,
		`"?token"?\s*[:=]\s*"([^"]+)"`, "cloud"),
	spec("vault", "Vault token", []string{".vault-token"}, Cloud, `(?s)^\s*(\S+)`, "cloud"),
	spec("pulumi", "Pulumi access token", []string{".pulumi/credentials.json"}, Cloud, "", "cloud"),
	spec("doctl", "DigitalOcean CLI token",
		[]string{"Library/Application Support/doctl/config.yaml", ".config/doctl/config.yaml"}, Cloud,
		`(?im)^\s*access-token:\s*(\S+)`, "cloud"),
	spec("fly", "Fly.io token", []string{".fly/config.yml"}, Cloud, `(?im)^\s*access_token:\s*(\S+)`, "cloud"),
	spec("vercel", "Vercel CLI token",
		[]string{"Library/Application Support/com.vercel.cli/auth.json", ".local/share/com.vercel.cli/auth.json"},
		Cloud, `"token"\s*:\s*"([^"]+)"`, "cloud"),
	spec("netlify", "Netlify CLI token",
		[]string{"Library/Preferences/netlify/config.json", ".config/netlify/config.json"}, Cloud,
		`"token"\s*:\s*"([^"]+)"`, "cloud"),
	spec("wrangler", "Cloudflare Wrangler token",
		[]string{"Library/Preferences/.wrangler/config/default.toml", ".wrangler/config/default.toml",
			".config/.wrangler/config/default.toml"}, Cloud,
		`(?im)^\s*(?:oauth_token|refresh_token|api_token)\s*=\s*"([^"]+)"`, "cloud"),
	spec("firebase", "Firebase CLI refresh token", []string{".config/configstore/firebase-tools.json"}, Cloud,
		`"refresh_token"\s*:\s*"([^"]+)"`, "cloud"),
	spec("stripe", "Stripe CLI key", []string{".config/stripe/config.toml"}, Service,
		`(?im)^\s*\w*(?:secret_key|api_key)\w*\s*=\s*['"]([^'"]+)`, "file-token"),
	spec("pgpass", "PostgreSQL password file", []string{".pgpass"}, Service, `(?m)^[^#\n]*:([^:\n]+)$`, "file-token"),
	spec("mycnf", "MySQL client password", []string{".my.cnf"}, Service, `(?im)^\s*password\s*=\s*(\S+)`, "file-token"),
	spec("rclone", "rclone remote credentials", []string{".config/rclone/rclone.conf"}, Cloud,
		`(?im)^\s*(?:token|pass|password|secret_access_key|key)\s*=\s*(\S.*)$`, "cloud"),
	spec("databricks", "Databricks token", []string{".databrickscfg"}, Cloud, `(?im)^\s*token\s*=\s*(\S+)`, "cloud"),
	spec("s3cfg", "S3 tool static keys", []string{".s3cfg", ".boto"}, Cloud,
		`(?im)^\s*(?:secret_key|aws_secret_access_key)\s*=\s*(\S+)`, "aws-static"),
	spec("age-key", "age / sops private key", []string{".config/sops/age/keys.txt"}, Cloud,
		`(AGE-SECRET-KEY-[A-Z0-9]+)`, "file-token"),
	spec("maven", "Maven repository password", []string{".m2/settings.xml"}, Service,
		`<password>([^<]+)</password>`, "file-token"),
	spec("gradle", "Gradle properties secrets", []string{".gradle/gradle.properties"}, Service,
		`(?im)^\s*\S*(?:password|token|secret|key)\S*\s*=\s*(\S+)`, "file-token"),
	spec("composer", "Composer auth file", []string{".composer/auth.json", ".config/composer/auth.json"}, Service,
		`"(?:token|password|[a-z.]+\.(?:com|org|io))"\s*:\s*"([^"]{8,})"`, "file-token"),
}

type knownFilesCollector struct{}

func (knownFilesCollector) Name() string { return "known-files" }

func (knownFilesCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	var out []Finding
	for _, s := range fileSpecs {
		for _, rel := range s.rels {
			if ctx.Err() != nil {
				return out, ErrPartial
			}
			if f, ok := s.collect(env, rel); ok {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func (s fileSpec) collect(env *Env, rel string) (Finding, bool) {
	p := filepath.Join(env.Home, rel)
	f := Finding{
		Layer: "files", Kind: s.kind, Title: s.title, Location: env.tilde(p),
		Fix: fixText[s.fix],
	}
	if s.rx == nil {
		if !presentAndReadable(env, p) {
			return f, false
		}
		f.Confidence = Medium
		f.Detail = "Credential store present and readable (contents not parsed)."
		f.Hits = []Hit{{Fingerprint: env.FingerprintLabel(s.kind + "|" + filepath.ToSlash(rel)), Class: s.class}}
		f.Notes = env.fileNotes(p, Static)
		return f, true
	}
	text, err := env.readFile(p, defaultReadLimit)
	if err != nil {
		return f, false
	}
	var ms matchSet
	for _, sm := range s.rx.FindAllSubmatch(text, -1) {
		if v := []byte(strings.TrimSpace(string(sm[1]))); looksReal(v) {
			ms.add(v, maxClass(s.class, tokenClass(v)), "") // the file's class is a floor (A-55)
		}
	}
	if len(ms.out) == 0 {
		return f, false
	}
	f.Hits = env.hits(ms.out)
	f.Notes = env.fileNotes(p, Static)
	return f, true
}

// presentAndReadable checks a presence-only store without reading it. The
// dataless check comes first: reading an evicted file downloads it (A-29).
// Opening without reading is the cheapest proof that this process may read
// it. Unverified on macOS (medium confidence): that open alone never
// materializes a dataless file; the dataless check makes that moot here.
func presentAndReadable(env *Env, p string) bool {
	if !env.allowProtected && env.resolvesIntoProtected(p) {
		return false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 || isDataless(fi) {
		return false
	}
	fh, err := os.Open(p)
	if err != nil {
		return false
	}
	fh.Close()
	return true
}

// newFileCollectors returns the known-file, AWS and SSH collectors.
func newFileCollectors(opts Options, fda string) []Collector {
	return []Collector{knownFilesCollector{}, awsCollector{}, sshCollector{}}
}
