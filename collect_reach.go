package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
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

// fdaProbes are folders readable only with Full Disk Access. A denied read
// fails silently and never prompts, so they are always checked (A-36).
var fdaProbes = []string{"Library/Mail", "Library/Messages", "Library/Safari"}

// inferFullDiskAccess returns yes if any FDA-only folder can be listed, no if
// every one that exists is denied, and unknown otherwise (R-03). The TCC.db
// check the prototype used gives no result on macOS 27. Unverified per
// terminal against System Settings (M5); confidence medium.
func inferFullDiskAccess(env *Env) string {
	if env.GOOS != "darwin" {
		return "unknown"
	}
	denied := 0
	for _, rel := range fdaProbes {
		switch probeDir(filepath.Join(env.Home, rel)) {
		case "readable":
			return "yes"
		case "blocked":
			denied++
		}
	}
	if denied > 0 {
		return "no" // every folder that exists was denied
	}
	return "unknown"
}

// probeDir lists at most one entry: "readable", "blocked" or "missing".
func probeDir(p string) string {
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return "blocked"
	}
	defer f.Close()
	if _, err := f.ReadDir(1); err != nil && !errors.Is(err, io.EOF) {
		return "blocked"
	}
	return "readable"
}

type reachTarget struct {
	label, rel string
	tcc        bool // may raise a consent prompt: probed only when allowed (decision 17)
	note       string
}

// reachTargets is the prototype's REACH_TARGETS. Its "open" label for app
// folders is dropped: macOS 27 reportedly blocks some of them without a
// prompt (R-04), so every target is measured rather than labelled.
var reachTargets = []reachTarget{
	{"Desktop", "Desktop", true, ""},
	{"Documents", "Documents", true, ""},
	{"Downloads", "Downloads", true, ""},
	{"iCloud Drive", "Library/Mobile Documents", true, ""},
	{"Cloud storage (Dropbox, Drive, OneDrive)", "Library/CloudStorage", true, ""},
	{"Photos library", "Pictures/Photos Library.photoslibrary", true, ""},
	{"Contacts", "Library/Application Support/AddressBook", true, ""},
	{"Calendars", "Library/Calendars", true, ""},
	{"Notes", "Library/Group Containers/group.com.apple.notes", true, ""},
	{"Mail", "Library/Mail", false, ""},
	{"Messages", "Library/Messages", false, ""},
	{"Safari data", "Library/Safari", false, ""},
	{"Chrome profile", "Library/Application Support/Google/Chrome", false,
		"History and bookmarks are plaintext; cookie values are encrypted with an app-gated Keychain key."},
	{"Firefox profiles", "Library/Application Support/Firefox/Profiles", false,
		"Session cookies are stored in plaintext; saved logins are decryptable unless a primary password is set."},
	{"Arc profile", "Library/Application Support/Arc", false, "Same model as Chrome."},
	{"Brave profile", "Library/Application Support/BraveSoftware/Brave-Browser", false, "Same model as Chrome."},
	{"Edge profile", "Library/Application Support/Microsoft Edge", false, "Same model as Chrome."},
	{"Slack data", "Library/Application Support/Slack", false, "Local cache and workspace metadata."},
	{"Signal data", "Library/Application Support/Signal", false, "Database is encrypted; key is Keychain-gated on current versions."},
}

const reachTargetBudget = 3 * time.Second

// reachCollector measures what else the same process can read. It emits no
// findings; its rows go to Snapshot.Reach (decision 1: not scored).
type reachCollector struct {
	probe  bool          // -probe-folders, or Full Disk Access inferred yes
	budget time.Duration // per target
	rows   []ReachRow
}

func newReachCollectors(opts Options, fda string) []Collector {
	return []Collector{&reachCollector{probe: opts.ProbeFolders || fda == "yes", budget: reachTargetBudget}}
}

func (*reachCollector) Name() string { return "reach" }

func (c *reachCollector) Section(s *Snapshot) { s.Reach = c.rows }

func (c *reachCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	if env.GOOS != "darwin" {
		return nil, ErrSkipped // every target is a macOS folder (A-37)
	}
	for _, t := range reachTargets {
		if ctx.Err() != nil {
			return nil, ErrPartial
		}
		p := filepath.Join(env.Home, t.rel)
		row := ReachRow{Label: t.label, Path: env.tilde(p), Note: t.note}
		if t.tcc && !c.probe {
			// Not even stat'ed: touching a protected path is what the opt-in avoids.
			row.Status = "not probed"
			c.rows = append(c.rows, row)
			continue
		}
		switch probeDir(p) {
		case "missing":
			continue
		case "blocked":
			row.Status = "blocked"
		default:
			row.Status = "readable"
			tctx, cancel := context.WithTimeout(ctx, c.budget)
			row.Bytes, row.Files, row.Partial = measure(tctx, p)
			cancel()
		}
		c.rows = append(c.rows, row)
	}
	return nil, nil
}

// measure totals sizes under root from directory listings and lstat only.
// No file is opened, so evicted (dataless) files are never downloaded
// (A-29). partial means the budget ran out and the totals are lower bounds.
func measure(ctx context.Context, root string) (total int64, files int, partial bool) {
	stack := []string{root}
	for len(stack) > 0 {
		if ctx.Err() != nil {
			return total, files, true
		}
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			switch {
			case e.IsDir():
				// Listing an evicted directory downloads it: count it, do not enter it.
				if fi, err := e.Info(); err == nil && !isDataless(fi) {
					stack = append(stack, filepath.Join(d, e.Name()))
				}
			case e.Type().IsRegular():
				if fi, err := e.Info(); err == nil {
					files++
					total += fi.Size()
				}
			}
		}
	}
	return total, files, false
}
