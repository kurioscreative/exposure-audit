package main

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Context identifies where the tool was launched from. Diffs compare only
// snapshots with the same Key.
type Context struct {
	App   string   `json:"app"`             // __CFBundleIdentifier, else TERM_PROGRAM, else "unknown" (A-05)
	Agent string   `json:"agent,omitempty"` // coding agent found in the parent chain
	Chain []string `json:"chain,omitempty"` // parent process names, for display only
	Key   string   `json:"key"`
}

// agentNames are process names that mean the shell runs under a coding agent.
// Unverified on macOS: an agent started through node may show as "node".
var agentNames = []string{"claude", "codex", "cursor-agent", "gemini", "aider", "goose"}

// launchContext builds the context key. Full Disk Access is deliberately not
// part of it: revoking it is a recommended fix and must not reset history (A-06).
func launchContext(ctx context.Context, env *Env) Context {
	c := Context{App: env.Plain("__CFBundleIdentifier")}
	if c.App == "" {
		c.App = env.Plain("TERM_PROGRAM")
	}
	if c.App == "" {
		c.App = "unknown"
	}
	c.Chain = parentChain(ctx, env)
	for _, name := range c.Chain {
		if slices.Contains(agentNames, name) {
			c.Agent = name
			break
		}
	}
	c.Key = c.App + "|plain"
	if c.Agent != "" {
		c.Key = c.App + "|agent"
	}
	return c
}

// parentChain walks up to 8 ancestors with /bin/ps. Inside tmux the chain
// ends at tmux (observed on Glenn's Mac), which is why it is display only.
func parentChain(ctx context.Context, env *Env) []string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var chain []string
	pid := env.PID
	for i := 0; i <= 8 && pid > 1; i++ {
		out, exit, err := env.Run(ctx, Cmd{Path: "/bin/ps", Args: []string{"-o", "ppid=,comm=", "-p", strconv.Itoa(pid)}})
		if err != nil || exit != 0 {
			break
		}
		ppid, comm, ok := strings.Cut(strings.TrimSpace(string(out)), " ")
		next, convErr := strconv.Atoi(ppid)
		if !ok || convErr != nil {
			break
		}
		if i > 0 { // i == 0 is this process
			chain = append(chain, filepath.Base(strings.TrimSpace(comm)))
		}
		pid = next
	}
	return chain
}
