package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Ambient collectors: the shell environment, shell startup and history
// files, and the dotenv sweep over project directories.

func newAmbientCollectors(opts Options, fda string) []Collector {
	return []Collector{
		envCollector{},
		shellFilesCollector{},
		&dotenvCollector{
			roots:        opts.Roots,
			maxDepth:     opts.MaxDepth,
			allowProtect: opts.ProbeFolders || fda == "yes",
			budget:       25 * time.Second,
		},
	}
}

// --- environment ---

// envSkip drops variables that name paths, sockets and helpers rather than
// hold secrets (prototype ENV_SKIP). Unlike the prototype it keeps *_URL:
// URLs can embed credentials (A-20).
var envSkip = regexp.MustCompile(`(?i)(_PATH|_FILE|_SOCK|_DIR|_HOME|_HELPER|_TYPE)$|^(SSH_AUTH_SOCK|GPG_TTY|XAUTHORITY)$`)

type envCollector struct{}

func (envCollector) Name() string { return "environment" }

func (envCollector) Collect(_ context.Context, env *Env) ([]Finding, error) {
	groups := map[Class][]Match{}
	names := sortedKeys(env.Environ)
	for _, name := range names {
		if envSkip.MatchString(name) {
			continue
		}
		for _, m := range envMatches(name, env.Environ[name].bytes()) {
			groups[m.Class] = append(groups[m.Class], m)
		}
	}
	_, awsSession := env.Environ["AWS_SESSION_TOKEN"]
	var out []Finding
	for _, class := range []Class{Propagation, Cloud, Agent, Service, Generic} {
		ms := groups[class]
		if len(ms) == 0 {
			continue
		}
		var vars []string
		allAWS := true
		for _, m := range ms {
			vars = append(vars, m.Name)
			allAWS = allAWS && strings.HasPrefix(m.Name, "AWS_")
		}
		slices.Sort(vars)
		vars = slices.Compact(vars)
		f := Finding{
			Layer: "ambient",
			Kind:  "env",
			Title: "Secrets exported in this shell's environment",
			// A fixed label per class keeps the SlotID stable when variables
			// come and go, so the diff can say rotated (A-46). Names, never
			// values, go in Detail and Hit.Name.
			Location: "environment (" + string(class) + ")",
			Lifetime: Static,
			Detail:   "Variables: " + strings.Join(vars, ", ") + ". Every child process, including install scripts, inherits these.",
			Fix:      fixText["env"],
			Hits:     env.hits(ms),
		}
		if class == Agent {
			f.Kind = "env-agent"
			f.Title = "Coding-agent session token in this shell's environment"
			f.Fix = fixText["agent"]
		}
		if awsSession && allAWS {
			f.Lifetime = Session
		}
		out = append(out, f)
	}
	return out, nil
}

// envMatches finds secrets in one variable: known token formats and URL
// credentials inside the value, else the whole value if the name looks
// secret-like. Every match is named after the variable.
func envMatches(name string, val []byte) []Match {
	var m matchSet
	nameClass := classForName(name)
	for _, p := range tokenPatterns {
		for _, v := range p.rx.FindAll(val, -1) {
			m.add(v, maxClass(p.class, nameClass), name)
		}
	}
	for _, sm := range urlCredRx.FindAllSubmatch(val, -1) {
		if plausibleByName(sm[2]) { // same value checks as extractSecrets (M3)
			m.add(sm[2], classForURL(string(sm[3]), name), name)
		}
	}
	if len(m.out) == 0 && nameOnlySecret(name, val) {
		m.add(val, nameClass, name)
	}
	return m.out
}

func maxClass(a, b Class) Class {
	if classRank[b] > classRank[a] {
		return b
	}
	return a
}

// --- shell startup and history files ---

var rcFiles = []string{".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile",
	".config/fish/config.fish", ".envrc", ".env"}

var historyFiles = []string{".zsh_history", ".bash_history", ".local/share/fish/fish_history", ".python_history",
	".psql_history", ".mysql_history", ".node_repl_history", ".irb_history",
	".viminfo"} // A-07

// historyDirs hold per-session history files (A-07): Apple Terminal writes
// ~/.zsh_sessions/*.history; bash's equivalent is ~/.bash_sessions/*.
var historyDirs = []struct{ dir, suffix string }{
	{".zsh_sessions", ".history"},
	{".bash_sessions", ""},
}

const textScanLimit = 8 << 20

type shellFilesCollector struct{}

func (shellFilesCollector) Name() string { return "shell-files" }

func (shellFilesCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	var out []Finding
	for _, rel := range rcFiles {
		out = appendScan(out, env, filepath.Join(env.Home, rel), "rc-literal", "Secrets hardcoded in a shell startup file", "rc", "")
	}
	hist := func(p string) {
		out = appendScan(out, env, p, "history", "Secrets left in command history", "history",
			"Pasted tokens and inline passwords persist here indefinitely.")
	}
	for _, rel := range historyFiles {
		hist(filepath.Join(env.Home, rel))
	}
	for _, hd := range historyDirs {
		entries, _ := os.ReadDir(filepath.Join(env.Home, hd.dir)) // sorted by name
		for _, d := range entries {
			if ctx.Err() != nil {
				return out, ErrPartial
			}
			if d.Type().IsRegular() && strings.HasSuffix(d.Name(), hd.suffix) {
				hist(filepath.Join(env.Home, hd.dir, d.Name()))
			}
		}
	}
	return out, nil
}

// appendScan scans one text file with the generic matcher and appends a
// finding if it holds secrets.
func appendScan(out []Finding, env *Env, p, kind, title, fix, detail string) []Finding {
	f, ok := scanTextFile(env, p, kind, title, fix, detail)
	if ok {
		out = append(out, f)
	}
	return out
}

func scanTextFile(env *Env, p, kind, title, fix, detail string) (Finding, bool) {
	text, err := env.readFile(p, textScanLimit)
	if err != nil {
		return Finding{}, false
	}
	ms := extractSecrets(text)
	if len(ms) == 0 {
		return Finding{}, false
	}
	return Finding{
		Layer:      "ambient",
		Kind:       kind,
		Title:      title,
		Location:   env.tilde(p),
		Lifetime:   Static,
		Detail:     detail,
		Notes:      env.fileNotes(p, Static),
		Confidence: Medium,
		Fix:        fixText[fix],
		Hits:       env.hits(ms),
	}, true
}

// --- dotenv sweep ---

var (
	dotenvRx     = regexp.MustCompile(`^\.env(\.[\w.\-]+)?$`)
	dotenvSafeRx = regexp.MustCompile(`(?i)(example|sample|template|dist|defaults?)$`)
	// Same capture as the known-files npm spec (prototype SPECS[0]).
	npmrcTokenRx = regexp.MustCompile(`(?im)^\s*(?://[^\s=]+:)?(?:_authToken|_auth|_password)\s*=\s*"?([^\s"]+)`)
	// Yarn Berry: npmAuthToken at the top level or under npmScopes/npmRegistries.
	yarnTokenRx = regexp.MustCompile(`(?m)^\s*npmAuthToken:\s*["']?([^\s"']+)`)
)

// dotenvCollector walks the sweep roots for project credential files. The
// home-level .env, .npmrc and .yarnrc.yml belong to other collectors.
type dotenvCollector struct {
	roots        []string
	maxDepth     int
	allowProtect bool
	budget       time.Duration
}

func (*dotenvCollector) Name() string { return "dotenv" }

func (c *dotenvCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()
	var out []Finding
	repos := gitRepos{env: env}
	seenDirs := map[string]bool{}
	seenConfigs := map[string]bool{}
	seenFiles := map[string]bool{} // nested or repeated roots reach a file twice (A-60)

	err := env.walk(ctx, c.roots, walkOpts{maxDepth: c.maxDepth, allowProtect: c.allowProtect}, func(dir string, d fs.DirEntry) {
		name, p := d.Name(), filepath.Join(dir, d.Name())
		if seenFiles[p] {
			return
		}
		seenFiles[p] = true
		if !seenDirs[dir] {
			// The walk never enters .git, so look at a repository's config
			// from its working directory (A-20). A repository root with no
			// files of its own is not noticed.
			seenDirs[dir] = true
			if f, ok := gitConfigFinding(env, dir, seenConfigs); ok {
				out = append(out, f)
			}
		}
		atHome := dir == env.Home
		switch {
		case dotenvRx.MatchString(name) && !dotenvSafeRx.MatchString(name):
			if atHome && name == ".env" {
				return // the shell-files collector owns ~/.env
			}
			if f, ok := scanTextFile(env, p, "dotenv", "Project .env file with secrets", "dotenv", ""); ok {
				tracked, known := repos.tracked(p)
				f.Committed = tracked
				if !known {
					f.Notes = append(f.Notes, "could not tell whether git tracks this file")
				}
				out = append(out, f)
			}
		case name == ".npmrc" && !atHome:
			out = appendCapture(out, env, p, npmrcTokenRx, "npm-token", "npm auth token in a project .npmrc")
		case name == ".yarnrc.yml" && !atHome:
			out = appendCapture(out, env, p, yarnTokenRx, "yarn-token", "npm auth token in a project .yarnrc.yml")
		case isRailsKey(dir, name):
			if f, ok := railsKeyFinding(env, p); ok {
				out = append(out, f)
			}
		}
	})
	return out, err
}

// appendCapture fingerprints group 1 of rx in a project registry config.
func appendCapture(out []Finding, env *Env, p string, rx *regexp.Regexp, kind, title string) []Finding {
	text, err := env.readFile(p, defaultReadLimit)
	if err != nil {
		return out
	}
	var ms []Match
	for _, sm := range rx.FindAllSubmatch(text, -1) {
		if looksReal(sm[1]) {
			ms = append(ms, Match{Value: NewSecret(sm[1]), Class: Propagation})
		}
	}
	if len(ms) == 0 {
		return out
	}
	return append(out, Finding{
		Layer: "ambient", Kind: kind, Title: title, Location: env.tilde(p),
		Lifetime: Static, Notes: env.fileNotes(p, Static), Fix: fixText["npm"], Hits: env.hits(ms),
	})
}

// isRailsKey matches config/master.key and config/credentials/*.key.
func isRailsKey(dir, name string) bool {
	if name == "master.key" && filepath.Base(dir) == "config" {
		return true
	}
	return strings.HasSuffix(name, ".key") && filepath.Base(dir) == "credentials" && filepath.Base(filepath.Dir(dir)) == "config"
}

// railsKeyFinding fingerprints the whole key file: it decrypts the app's
// credentials file, which usually holds service keys.
func railsKeyFinding(env *Env, p string) (Finding, bool) {
	b, err := env.readFile(p, 4096)
	if err != nil {
		return Finding{}, false
	}
	v := []byte(strings.TrimSpace(string(b)))
	if len(v) == 0 {
		return Finding{}, false
	}
	return Finding{
		Layer: "ambient", Kind: "rails-key", Title: "Rails credentials key", Location: env.tilde(p),
		Lifetime: Static, Notes: env.fileNotes(p, Static), Fix: fixText["file-token"],
		Detail: "Decrypts the app's encrypted credentials file.",
		Hits:   []Hit{{Fingerprint: env.Fingerprint(NewSecret(v)), Class: Service}},
	}, true
}

// gitConfigFinding scans dir/.git's config, once per config file, so a
// worktree and its main repository report the shared config once.
func gitConfigFinding(env *Env, dir string, seen map[string]bool) (Finding, bool) {
	gd, err := gitDir(env, dir)
	if err != nil {
		return Finding{}, false
	}
	p := gitConfigPath(env, gd)
	if seen[p] {
		return Finding{}, false
	}
	seen[p] = true
	f, ok := scanTextFile(env, p, "git-config", "Credentials in a repository's git config", "file-token",
		"Remote URLs with an embedded token are sent to every git command and readable by any script.")
	if !ok {
		return f, false
	}
	f.Confidence = High
	if slices.ContainsFunc(f.Hits, func(h Hit) bool { return h.Class == Propagation }) {
		f.Fix = fixText["github"]
	}
	return f, true
}
