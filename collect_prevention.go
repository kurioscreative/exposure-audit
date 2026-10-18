package main

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Prevention (decision 19, A-32): whether package managers run install
// scripts and whether a release-age delay is set. Unscored, config files
// only, and only fixed vocabulary leaves this file: a .npmrc also holds
// tokens, so no parsed value is ever copied into a row.
//
// "on" means the protective setting is in effect (scripts blocked, delay
// set), "off" means it is explicitly disabled, "not configured" means the
// key is absent from the file read here, and "default" means it is absent
// but the tool's current release protects without it. Only the per-user
// files below are read; project-level files can override them and are not
// checked.

const (
	stateOn            = "on"
	stateOff           = "off"
	stateNotConfigured = "not configured"
	stateDefault       = "default"
)

type preventionCollector struct {
	rows []PreventionRow
}

func (*preventionCollector) Name() string { return "prevention" }

func (c *preventionCollector) Section(s *Snapshot) { s.Prevention = c.rows }

func (c *preventionCollector) Collect(_ context.Context, env *Env) ([]Finding, error) {
	c.rows = append(c.rows, npmRows(env)...)
	c.rows = append(c.rows, yarnRows(env)...)
	c.rows = append(c.rows, pnpmRows(env)...)
	c.rows = append(c.rows, bunRows(env)...)
	return nil, nil
}

func row(tool, setting, state, fix string) PreventionRow {
	r := PreventionRow{Tool: tool, Setting: setting, State: state}
	if state != stateOn {
		r.Fix = fix
	}
	return r
}

// byDefault reports an absent key as "default" with defaultFix, for a
// setting the tool's current release already protects.
func byDefault(state, fix, defaultFix string) (string, string) {
	if state == stateNotConfigured {
		return stateDefault, defaultFix
	}
	return state, fix
}

// npm reads ~/.npmrc, the per-user config.
// https://docs.npmjs.com/cli/v11/using-npm/config (ignore-scripts: Boolean,
// default false; min-release-age: null or Number of days, default null).
func npmRows(env *Env) []PreventionRow {
	kv := parseINI(readConfig(env, ".npmrc"))
	return []PreventionRow{
		row("npm", "ignore-scripts", boolState(kv, "ignore-scripts", true),
			"Add ignore-scripts=true to ~/.npmrc and run the build scripts you need explicitly (npm rebuild <pkg>)."),
		row("npm", "min-release-age", ageState(kv, "min-release-age"),
			"Add min-release-age=<days> to ~/.npmrc so new versions wait a few days before npm installs them."),
	}
}

// Yarn Berry reads .yarnrc.yml files from the project's parent directories,
// so ~/.yarnrc.yml applies to projects under the home.
// https://yarnpkg.com/configuration/yarnrc (enableScripts: the page states
// false is the default in the current release; npmMinimalAgeGate: a duration
// such as "1w"). Older Yarn releases defaulted enableScripts to true, so a
// missing key is reported as default rather than on.
func yarnRows(env *Env) []PreventionRow {
	kv := parseYAMLTop(readConfig(env, ".yarnrc.yml"))
	scripts, fix := byDefault(boolState(kv, "enableScripts", false),
		"Add enableScripts: false to ~/.yarnrc.yml and allow builds per package with dependenciesMeta.",
		"Current Yarn blocks install scripts by default; add enableScripts: false to ~/.yarnrc.yml to be sure on older versions, and allow builds per package with dependenciesMeta.")
	return []PreventionRow{
		row("Yarn", "enableScripts", scripts, fix),
		row("Yarn", "npmMinimalAgeGate", ageState(kv, "npmMinimalAgeGate"),
			"Add npmMinimalAgeGate: 3d to ~/.yarnrc.yml so new versions wait before Yarn installs them."),
	}
}

// pnpm keeps global settings in config.yaml (camelCase YAML); its rc file
// holds only registry and auth settings since v11, but older releases read
// kebab-case settings from it, so both are read and config.yaml wins.
// https://pnpm.io/configuring (macOS: ~/Library/Preferences/pnpm/config.yaml
// and .../rc; elsewhere ~/.config/pnpm/).
// https://pnpm.io/settings/build (ignoreScripts default false;
// dangerouslyAllowAllBuilds default false, so a row appears only when it is
// set true, as "off": absent or false is the safe default, not a gap;
// onlyBuiltDependencies was removed in v11 and replaced by allowBuilds, and
// unlisted packages' build scripts are disallowed by default, so it is not
// reported, and an absent ignoreScripts is "default").
// https://pnpm.io/settings/dependency-resolution (minimumReleaseAge: minutes;
// default 1440 since v11, 0 before, so an absent key is "default").
func pnpmRows(env *Env) []PreventionRow {
	dir := ".config/pnpm"
	if env.GOOS == "darwin" {
		dir = "Library/Preferences/pnpm"
	}
	kv := parseINI(readConfig(env, dir+"/rc"))
	for k, v := range parseYAMLTop(readConfig(env, dir+"/config.yaml")) {
		kv[k] = v
	}
	alias(kv, "ignore-scripts", "ignoreScripts")
	alias(kv, "dangerously-allow-all-builds", "dangerouslyAllowAllBuilds")
	alias(kv, "minimum-release-age", "minimumReleaseAge")
	age, ageFix := byDefault(ageState(kv, "minimumReleaseAge"),
		"Set minimumReleaseAge (minutes, e.g. 4320) in pnpm's global config.yaml.",
		"pnpm 11+ already waits 1 day; set minimumReleaseAge (minutes, e.g. 4320) in pnpm's global config.yaml to be sure on older versions or to wait longer.")
	scripts, scriptsFix := byDefault(boolState(kv, "ignoreScripts", true),
		"Set ignoreScripts: true in pnpm's global config.yaml, or rely on allowBuilds to approve build scripts per package.",
		"pnpm 10+ blocks dependency build scripts unless allowBuilds approves them; set ignoreScripts: true in pnpm's global config.yaml to be sure on older versions.")
	rows := []PreventionRow{row("pnpm", "ignoreScripts", scripts, scriptsFix)}
	if boolState(kv, "dangerouslyAllowAllBuilds", false) == stateOff {
		rows = append(rows, row("pnpm", "dangerouslyAllowAllBuilds", stateOff,
			"Remove dangerouslyAllowAllBuilds and approve build scripts per package with allowBuilds."))
	}
	return append(rows, row("pnpm", "minimumReleaseAge", age, ageFix))
}

// Bun reads a global $HOME/.bunfig.toml (or $XDG_CONFIG_HOME/.bunfig.toml,
// which is not read here: XDG_CONFIG_HOME is not on PlainEnv).
// https://bun.com/docs/runtime/bunfig ([install] ignoreScripts: boolean,
// default false; minimumReleaseAge: seconds, default null).
// https://bun.com/docs/install/lifecycle (Bun skips dependencies' lifecycle
// scripts unless the package is in trustedDependencies or Bun's default
// trusted list, so an absent ignoreScripts is "default").
func bunRows(env *Env) []PreventionRow {
	kv := parseTOMLSection(readConfig(env, ".bunfig.toml"), "install")
	scripts, fix := byDefault(boolState(kv, "ignoreScripts", true),
		"Add ignoreScripts = true under [install] in ~/.bunfig.toml.",
		"Bun skips dependency lifecycle scripts by default, but its trusted list still runs them for popular packages; add ignoreScripts = true under [install] in ~/.bunfig.toml to close that and to be sure on older versions.")
	return []PreventionRow{
		row("Bun", "install.ignoreScripts", scripts, fix),
		row("Bun", "install.minimumReleaseAge", ageState(kv, "minimumReleaseAge"),
			"Add minimumReleaseAge = <seconds> under [install] in ~/.bunfig.toml (259200 is three days)."),
	}
}

func readConfig(env *Env, rel string) string {
	b, err := env.readFile(filepath.Join(env.Home, rel), defaultReadLimit)
	if err != nil {
		return ""
	}
	return string(b)
}

// boolState maps a boolean key to on/off. protective is the value that
// blocks scripts.
func boolState(kv map[string]string, key string, protective bool) string {
	v, ok := kv[key]
	if !ok {
		return stateNotConfigured
	}
	b, err := strconv.ParseBool(strings.ToLower(v))
	if err != nil {
		return stateNotConfigured
	}
	if b == protective {
		return stateOn
	}
	return stateOff
}

var zeroAge = regexp.MustCompile(`^0+(\.0+)?[a-z]*$`)

// ageState: any non-zero delay is on; zero is off.
func ageState(kv map[string]string, key string) string {
	v, ok := kv[key]
	if !ok || v == "" || v == "null" {
		return stateNotConfigured
	}
	if zeroAge.MatchString(strings.ToLower(v)) {
		return stateOff
	}
	return stateOn
}

func alias(kv map[string]string, from, to string) {
	if v, ok := kv[from]; ok {
		if _, set := kv[to]; !set {
			kv[to] = v
		}
	}
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

// parseINI reads key=value lines (npmrc format); the last value wins.
func parseINI(text string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[strings.TrimSpace(k)] = unquote(v)
		}
	}
	return kv
}

// parseYAMLTop reads unindented "key: value" lines, which is all these
// settings use.
func parseYAMLTop(text string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			v, _, _ = strings.Cut(v, " #")
			kv[strings.TrimSpace(k)] = unquote(v)
		}
	}
	return kv
}

// parseTOMLSection reads key = value lines inside [section], and
// section.key = value lines at the top level.
func parseTOMLSection(text, section string) map[string]string {
	kv := map[string]string{}
	cur := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "[") {
			cur = strings.TrimSpace(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v, _, _ = strings.Cut(v, " #")
		switch {
		case cur == section:
			kv[k] = unquote(v)
		case cur == "" && strings.HasPrefix(k, section+"."):
			kv[strings.TrimPrefix(k, section+".")] = unquote(v)
		}
	}
	return kv
}
