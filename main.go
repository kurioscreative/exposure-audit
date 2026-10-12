package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const version = "0.2.0-dev"

// Options are the parsed command-line flags.
type Options struct {
	Open         bool
	JSON         bool
	ProbeFolders bool
	SkipKeychain bool
	Roots        []string
	MaxDepth     int
	Sanitize     bool // -sanitize-keychain-sample
}

// App is the whole tool, runnable in-process so tests never exec the binary
// against a real home.
type App struct {
	Env            *Env
	Stdout, Stderr io.Writer
	Collectors     []Collector // nil means defaultCollectors
	Deadline       time.Duration
	OpenWait       time.Duration // how long the browser gets to load report.html
}

func main() {
	env, err := RealEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "exposure-audit: cannot determine the home directory")
		os.Exit(2)
	}
	app := &App{Env: env, Stdout: os.Stdout, Stderr: os.Stderr, Deadline: 60 * time.Second, OpenWait: 5 * time.Second}
	os.Exit(app.Main(os.Args[1:]))
}

func (a *App) parseFlags(args []string) (Options, error) {
	var o Options
	var roots string
	fs := flag.NewFlagSet("exposure-audit", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.BoolVar(&o.Open, "open", false, "write the HTML report, open it, then delete it")
	fs.BoolVar(&o.JSON, "json", false, "print the snapshot as JSON")
	fs.BoolVar(&o.ProbeFolders, "probe-folders", false, "also read TCC-protected folders (may raise a macOS prompt)")
	fs.BoolVar(&o.SkipKeychain, "skip-keychain", false, "skip the login keychain access-list check")
	fs.StringVar(&roots, "roots", "", "comma-separated directories for the .env sweep (default: home)")
	fs.IntVar(&o.MaxDepth, "max-depth", 5, "depth limit for the .env sweep")
	fs.BoolVar(&o.Sanitize, "sanitize-keychain-sample", false, "print a sanitized login keychain dump for testdata/, then exit")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 || o.MaxDepth < 0 {
		fs.Usage()
		return o, flag.ErrHelp
	}
	o.Roots = []string{a.Env.Home}
	if roots != "" {
		o.Roots = strings.Split(roots, ",")
	}
	return o, nil
}

// Main runs the tool and returns the exit code (decision 18): 0 complete;
// 1 report produced but a collector failed, timed out or was partial, or an
// output was withheld by the leak check; 2 usage error or unusable state.
func (a *App) Main(args []string) int {
	opts, err := a.parseFlags(args)
	if err != nil {
		return 2
	}
	if opts.Sanitize {
		return a.sanitizeKeychainSample()
	}
	stateDir, err := prepareStateDir(a.Env.Home)
	if err != nil {
		fmt.Fprintln(a.Stderr, "exposure-audit: the state directory ~/.exposure-audit is unusable")
		return 2
	}
	salt, err := loadSalt(stateDir)
	if err != nil {
		fmt.Fprintln(a.Stderr, "exposure-audit: cannot read or create the salt in ~/.exposure-audit")
		return 2
	}

	a.Env.salt = NewSecret(salt)

	launch := launchContext(context.Background(), a.Env)
	// Synchronous and before the collectors: the sweep depends on it.
	fda := inferFullDiskAccess(a.Env)
	collectors := a.Collectors
	if collectors == nil {
		collectors = defaultCollectors(opts, fda)
	}
	res := runCollectors(collectors, a.Env, a.Deadline)
	snap := &Snapshot{
		Schema:         snapshotSchema,
		Version:        version,
		Time:           a.Env.Now.UTC(),
		Context:        launch,
		FullDiskAccess: fda,
		Collectors:     res.Statuses,
		Errors:         res.Errors,
		Findings:       res.Findings,
	}
	for _, c := range collectors {
		if sec, ok := c.(sectioner); ok && res.Statuses[c.Name()] != Timeout {
			sec.Section(snap)
		}
	}
	sortFindings(snap.Findings)
	snap.Credentials, snap.Items, snap.Total = score(snap.Findings)
	if fda == "yes" {
		snap.Items = append([]Item{pinnedFDAItem(launch.App)}, snap.Items...)
	}
	if prev := previousSnapshot(stateDir, launch.Key); prev != nil {
		snap.Diff = diffSnapshots(prev, snap)
	}

	code := 0
	for _, st := range snap.Collectors {
		if st != Complete && st != Skipped {
			code = 1
		}
	}
	if err := a.emit(snap, opts, stateDir, salt); errors.Is(err, errOutputLeak) {
		fmt.Fprintln(a.Stderr, "exposure-audit: output withheld (output-leak): a collected secret appeared in the rendered output; nothing was written")
		return 1
	} else if err != nil {
		fmt.Fprintln(a.Stderr, "exposure-audit: could not write the snapshot to ~/.exposure-audit")
		return 2
	}
	return code
}

// emit renders every output, checks all of them for leaks before writing any
// (A-26), then writes history, stdout and the -open report.
func (a *App) emit(snap *Snapshot, opts Options, stateDir string, salt []byte) error {
	history, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		return err
	}
	stdout := renderSummary(snap)
	if opts.JSON {
		stdout = append(history, '\n')
	}
	var report []byte
	if opts.Open {
		if report, err = renderReport(snap); err != nil {
			return err
		}
	}
	fps := map[string]bool{}
	for _, f := range snap.Findings {
		for _, h := range f.Hits {
			fps[h.Fingerprint] = true
		}
	}
	for _, out := range [][]byte{history, stdout, report} {
		if err := checkLeak(out, salt, fps); err != nil {
			return err
		}
	}

	if _, err := writeSnapshotFile(stateDir, snap.Time.Format("20060102T150405Z"), history); err != nil {
		return err
	}
	a.Stdout.Write(stdout)
	if opts.Open {
		a.openReport(stateDir, report)
	}
	return nil
}

// openReport writes report.html, opens it, gives the browser OpenWait to
// load it, and deletes it (decision 15).
func (a *App) openReport(stateDir string, report []byte) {
	p := filepath.Join(stateDir, "report.html")
	os.Remove(p)
	if err := writeExclusive(p, report); err != nil {
		fmt.Fprintln(a.Stderr, "exposure-audit: could not write the report")
		return
	}
	defer os.Remove(p)
	if _, exit, err := a.Env.Run(context.Background(), Cmd{Path: "/usr/bin/open", Args: []string{p}}); err != nil || exit != 0 {
		fmt.Fprintln(a.Stderr, "exposure-audit: could not open the report")
		return
	}
	time.Sleep(a.OpenWait)
}

// defaultCollectors lists every collector. fda is the Full Disk Access
// inference, which decides whether walks may enter protected folders.
func defaultCollectors(opts Options, fda string) []Collector {
	return []Collector{}
}

// sortFindings gives findings a stable order regardless of collector timing.
func sortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Location, b.Location), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID))
	})
}
