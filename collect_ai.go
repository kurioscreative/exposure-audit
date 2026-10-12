package main

import (
	"context"
	"os"
	"path/filepath"
)

// aiFiles are AI tool and MCP configs that often embed long-lived keys
// (prototype AI_FILES).
var aiFiles = []string{
	".claude.json", ".claude/settings.json", ".claude/.credentials.json",
	"Library/Application Support/Claude/claude_desktop_config.json",
	".cursor/mcp.json", ".codeium/windsurf/mcp_config.json",
	".codex/auth.json", ".codex/config.toml",
	".gemini/settings.json", ".gemini/oauth_creds.json",
	".config/github-copilot/hosts.json", ".config/github-copilot/apps.json",
	".continue/config.json", ".continue/config.yaml", ".aider.conf.yml",
	".config/goose/config.yaml", ".config/zed/settings.json",
	"Library/Application Support/Code/User/mcp.json",
	"Library/Application Support/Code/User/settings.json",
	"Library/Application Support/Cursor/User/settings.json",
}

type aiConfigCollector struct{}

func (aiConfigCollector) Name() string { return "ai-configs" }

func (aiConfigCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	var out []Finding
	for _, rel := range aiFiles {
		if ctx.Err() != nil {
			return out, ErrPartial
		}
		p := filepath.Join(env.Home, rel)
		text, err := env.readFile(p, defaultReadLimit)
		if err != nil {
			continue // missing, unreadable or not local
		}
		ms := extractSecrets(text)
		if len(ms) == 0 {
			continue
		}
		out = append(out, Finding{
			Layer:      "ai",
			Kind:       "ai-config",
			Title:      "API keys in an AI tool or MCP config",
			Location:   env.tilde(p),
			Detail:     "MCP server entries often embed long-lived keys in env blocks.",
			Notes:      env.fileNotes(p, Static),
			Confidence: Medium,
			Fix:        fixText["ai"],
			Hits:       env.hits(ms),
		})
	}
	return out, nil
}

const opCLIFix = "If you do not use the 1Password CLI from terminals, turn off its app integration (1Password > Settings > Developer); otherwise lock 1Password before running package installs."

// opCLICollector infers decision 10's windowed vault access. Nothing is
// executed: both checks are stat calls. Unverified on macOS (low confidence):
// whether the CLI integration is actually on, and how long the approval
// window lasts, cannot be seen without running op.
type opCLICollector struct{}

func newOpCLICollector() *opCLICollector { return &opCLICollector{} }

// Paths under Env.Root: the 1Password app bundle, and where Homebrew installs op.
const opAppPath = "Applications/1Password.app"

var opPaths = []string{"opt/homebrew/bin/op", "usr/local/bin/op"}

func (*opCLICollector) Name() string { return "1password-cli" }

func (c *opCLICollector) Collect(_ context.Context, env *Env) ([]Finding, error) {
	if env.GOOS != "darwin" {
		return nil, ErrSkipped
	}
	if fi, err := os.Stat(filepath.Join(env.Root, opAppPath)); err != nil || !fi.IsDir() {
		return nil, nil
	}
	for _, p := range opPaths {
		if fi, err := os.Stat(filepath.Join(env.Root, p)); err == nil && fi.Mode().IsRegular() {
			return []Finding{{
				Layer:      "ambient",
				Kind:       "op-cli",
				Title:      "1Password vault reachable through the op CLI",
				Location:   "1Password CLI (op) with the 1Password app",
				Gate:       Windowed,
				Confidence: Low,
				Detail:     "If the 1Password app's CLI integration is on, a script in a terminal that unlocked `op` in the last ~10 minutes can read the vault without a prompt.",
				Fix:        opCLIFix,
				// Propagation: a vault usually holds publishing tokens (decision 10).
				Hits: []Hit{{Fingerprint: env.FingerprintLabel("op-cli"), Class: Propagation}},
			}}, nil
		}
	}
	return nil, nil
}

// newAICollectors returns the AI-config, 1Password CLI and Prevention collectors.
func newAICollectors(opts Options, fda string) []Collector {
	return []Collector{aiConfigCollector{}, newOpCLICollector(), &preventionCollector{}}
}
