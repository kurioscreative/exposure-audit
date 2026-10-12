package main

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// M4: credential helpers hand their token to any caller who asks. They are
// never executed (decision 14, A-23); whether they would answer silently is
// inferred from their configuration plus the Keychain access list. This only
// enriches Keychain findings and never adds new ones, so nothing is counted
// twice. Rotation comes from the item's mdat, like any Keychain finding.
//
// gcloud's active account and AWS sso_session are not handled here: they have
// no Keychain item to enrich, and reporting them would need a new finding
// (question for Glenn in the M4 handback).

type helperConfig struct {
	gitOSXKeychain bool // credential.helper is osxkeychain
	ghInKeychain   bool // gh hosts.yml exists without an oauth_token
	dockerKeychain bool // credsStore or a credHelpers entry is osxkeychain or desktop
}

func loadHelperConfig(env *Env) helperConfig {
	var h helperConfig
	for _, rel := range []string{".gitconfig", ".config/git/config"} {
		if b, err := env.readFile(filepath.Join(env.Home, rel), defaultReadLimit); err == nil && gitHelperIsOSXKeychain(string(b)) {
			h.gitOSXKeychain = true
		}
	}
	if b, err := env.readFile(filepath.Join(env.Home, ".config/gh/hosts.yml"), defaultReadLimit); err == nil {
		h.ghInKeychain = !ghOAuthTokenRx.Match(b)
	}
	if b, err := env.readFile(filepath.Join(env.Home, ".docker/config.json"), defaultReadLimit); err == nil {
		var cfg struct {
			CredsStore  string            `json:"credsStore"`
			CredHelpers map[string]string `json:"credHelpers"`
		}
		if json.Unmarshal(b, &cfg) == nil {
			keychainHelper := func(s string) bool { return s == "osxkeychain" || s == "desktop" }
			h.dockerKeychain = keychainHelper(cfg.CredsStore)
			for _, v := range cfg.CredHelpers {
				h.dockerKeychain = h.dockerKeychain || keychainHelper(v)
			}
		}
	}
	return h
}

var (
	ghOAuthTokenRx  = regexp.MustCompile(`(?m)^\s*oauth_token:`)
	gitSectionRx    = regexp.MustCompile(`^\[\s*([A-Za-z0-9.\-]+)`)
	gitHelperLineRx = regexp.MustCompile(`(?i)^helper\s*=\s*(.*)$`)
)

// gitHelperIsOSXKeychain reads `helper = osxkeychain` from any [credential]
// section, including URL-scoped ones.
func gitHelperIsOSXKeychain(text string) bool {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if m := gitSectionRx.FindStringSubmatch(s); m != nil {
			section = strings.ToLower(m[1])
			continue
		}
		if section != "credential" {
			continue
		}
		if m := gitHelperLineRx.FindStringSubmatch(s); m != nil {
			v := strings.Trim(strings.TrimSpace(m[1]), `"`)
			if v == "osxkeychain" || strings.HasSuffix(v, "git-credential-osxkeychain") {
				return true
			}
		}
	}
	return false
}

func trustsTool(v kcVerdict, match func(base string) bool) (string, bool) {
	for _, t := range v.tools {
		if match(filepath.Base(t)) {
			return t, true
		}
	}
	return "", false
}

// forgeClass is propagation for GitHub, GitLab and Bitbucket servers.
func forgeClass(server string) Class {
	s := strings.ToLower(server)
	for _, f := range []string{"github", "gitlab", "bitbucket"} {
		if strings.Contains(s, f) {
			return Propagation
		}
	}
	return Service
}

// enrich rewrites a silent Keychain finding when a configured helper hands
// out the item. It never changes the gate: an item the classifier did not
// find silent is not enriched. Server and host names, which come from the
// Keychain, go only into Live fields (decision 16).
func (h helperConfig) enrich(it *kcItem, v kcVerdict, f *Finding) {
	if v.access != kcSilent {
		return
	}
	svc := kcService(it)
	setClass := func(c Class) {
		for i := range f.Hits {
			f.Hits[i].Class = c
		}
	}
	_, viaGit := trustsTool(v, func(b string) bool { return b == "git-credential-osxkeychain" })
	_, viaSecurity := trustsTool(v, func(b string) bool { return b == "security" })
	dockerTool, viaDocker := trustsTool(v, func(b string) bool { return strings.HasPrefix(b, "docker-credential-") })
	switch {
	case h.gitOSXKeychain && it.class == "inet" && viaGit:
		server := it.attrs["srvr"]
		f.Title = "Git credentials in the Keychain, usable by any process through git-credential-osxkeychain"
		f.LiveTitle = "Git credentials for " + server + ", usable by any process through git-credential-osxkeychain"
		f.Fix = fixText["github"]
		setClass(forgeClass(server))
	case h.ghInKeychain && strings.HasPrefix(svc, "gh:") && (viaSecurity || v.anyApp):
		f.Title = "GitHub CLI token, readable by any process through /usr/bin/security"
		f.LiveTitle = f.Title + " (" + strings.TrimPrefix(svc, "gh:") + ")"
		f.Fix = fixText["github"]
		setClass(Propagation)
	case h.dockerKeychain && it.attrs["labl"] == "Docker Credentials" && viaDocker:
		name := filepath.Base(dockerTool)
		f.Title = "Docker registry credentials, usable by any process through " + name
		f.LiveTitle = "Docker registry credentials for " + it.attrs["srvr"] + ", usable by any process through " + name
		f.Fix = fixText["docker"]
		setClass(Service)
	}
}
