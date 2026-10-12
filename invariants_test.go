package main

// The mechanical checks from HANDOFF section 6. They must pass before and
// after every collector is added.

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNoNetworkPackages(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range strings.Fields(string(out)) {
		// Exact match: html/template legitimately pulls in net/url and net/netip (A-04).
		if dep == "net" || dep == "net/http" {
			t.Errorf("binary links %s (invariant 2)", dep)
		}
	}
}

func TestStandardLibraryOnly(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, "require") {
			t.Errorf("go.mod has a require line: %q (invariant 4)", line)
		}
	}
	if _, err := os.Stat("go.sum"); err == nil {
		t.Error("go.sum exists (invariant 4)")
	}
}

func TestReadOnlyAndStatePermissions(t *testing.T) {
	for _, args := range [][]string{nil, {"-open"}, {"-json"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fx := newFixture(t)
			fx.write(".npmrc", "registry=x\n")
			fx.write("code/app/.env", "A=b\n")
			var reportSeen bool
			fx.stubs["/usr/bin/open"] = func(a []string) ([]byte, int) {
				_, err := os.Stat(a[0])
				reportSeen = err == nil
				return nil, 0
			}
			before := tree(t, fx.home)
			if r := fx.runApp(nil, args...); r.code != 0 {
				t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
			}
			after := tree(t, fx.home)
			for p, st := range before {
				if p == "." { // creating ~/.exposure-audit updates the home's mtime and size
					st.mod, st.size = after[p].mod, after[p].size
				}
				if after[p] != st {
					t.Errorf("%s changed", p)
				}
			}
			for p, st := range after {
				if _, ok := before[p]; ok {
					continue
				}
				if p != stateDirName && !strings.HasPrefix(p, stateDirName+string(filepath.Separator)) {
					t.Errorf("tool created %s outside the state directory", p)
					continue
				}
				want := os.FileMode(0o600)
				if st.mode.IsDir() {
					want = 0o700
				}
				if st.mode.Perm() != want {
					t.Errorf("%s has mode %v, want %v", p, st.mode.Perm(), want)
				}
				if filepath.Base(p) == "report.html" {
					t.Error("report.html remains after the run")
				}
			}
			if slices.Contains(args, "-open") && !reportSeen {
				t.Error("open was not given an existing report")
			}
		})
	}
}

type testCollector struct {
	name string
	fn   func(ctx context.Context, env *Env) ([]Finding, error)
}

func (c testCollector) Name() string { return c.name }
func (c testCollector) Collect(ctx context.Context, env *Env) ([]Finding, error) {
	return c.fn(ctx, env)
}

func TestCollectorContainment(t *testing.T) {
	secretText := "contains " + marker("errtext")
	cs := []Collector{
		testCollector{"panics", func(context.Context, *Env) ([]Finding, error) { panic(secretText) }},
		testCollector{"errors", func(context.Context, *Env) ([]Finding, error) { return nil, errors.New(secretText) }},
		testCollector{"goroutine-panics", func(ctx context.Context, _ *Env) ([]Finding, error) {
			Go(ctx, func() { panic(secretText) })
			return nil, nil
		}},
		testCollector{"blocks", func(context.Context, *Env) ([]Finding, error) {
			select {} // ignores ctx entirely, like a hung mount
		}},
		testCollector{"fine", func(context.Context, *Env) ([]Finding, error) { return nil, nil }},
	}
	fx := newFixture(t)
	var out, errb strings.Builder
	app := &App{Env: fx.env(), Stdout: &out, Stderr: &errb, Collectors: cs, Deadline: 200 * time.Millisecond}
	start := time.Now()
	code := app.Main([]string{"-json"})
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("run took %v; the deadline was not enforced", el)
	}
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	snap := decodeSnapshot(t, out.String())
	want := map[string]string{"panics": "panic", "errors": "error", "goroutine-panics": "panic", "blocks": "timeout"}
	if len(snap.Errors) != len(want) {
		t.Fatalf("Errors = %+v, want %d entries", snap.Errors, len(want))
	}
	for _, e := range snap.Errors {
		if want[e.Collector] != e.Category {
			t.Errorf("error entry %+v, want category %q", e, want[e.Collector])
		}
	}
	if snap.Collectors["fine"] != Complete {
		t.Errorf("fine collector status %q", snap.Collectors["fine"])
	}
	if strings.Contains(out.String()+errb.String(), marker("errtext")) {
		t.Error("dynamic error text reached the output")
	}
}

func TestSubprocessesAreAllowlisted(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	fx.runApp(nil, "-open")
	fx.mu.Lock()
	defer fx.mu.Unlock()
	for _, c := range fx.ran {
		if !slices.Contains(AllowedPrograms, c.Path) {
			t.Errorf("ran %q, outside invariant 8", c.Path)
		}
	}
}

func TestLeakThroughLocationAbortsWrite(t *testing.T) {
	fx := newFixture(t)
	val := fx.secret("ghp_", 36)
	leaky := testCollector{"leaky", func(_ context.Context, env *Env) ([]Finding, error) {
		s := NewSecret([]byte(val))
		return []Finding{{
			Kind:     "git-url",
			Title:    "Token in a remote URL",
			Location: "https://x-access-token:" + val + "@github.com/", // the A-26 mistake
			Hits:     []Hit{{Fingerprint: env.Fingerprint(s), Class: Propagation}},
		}}, nil
	}}
	for _, args := range [][]string{nil, {"-json"}, {"-open"}} {
		r := fx.runApp([]Collector{leaky}, args...)
		if r.code != 1 {
			t.Errorf("%v: exit %d, want 1", args, r.code)
		}
		if r.stdout != "" {
			t.Errorf("%v: stdout written despite the leak", args)
		}
		if !strings.Contains(r.stderr, "output-leak") {
			t.Errorf("%v: stderr %q lacks the category", args, r.stderr)
		}
		fx.assertNoMarkers(r.stdout, r.stderr)
	}
	if h := fx.historyFiles(); len(h) != 0 {
		t.Errorf("history written despite the leak: %d files", len(h))
	}
}

func TestEnvironmentSecretsNeverReachOutput(t *testing.T) {
	fx := newFixture(t)
	fx.setenv("MY_SERVICE_TOKEN", fx.secret("", 32))
	fx.setenv("GITHUB_TOKEN", fx.secret("ghp_", 36))
	for _, args := range [][]string{nil, {"-json"}} {
		r := fx.runApp(nil, args...)
		fx.assertNoMarkers(r.stdout, r.stderr)
	}
}

func TestExitCodes(t *testing.T) {
	fx := newFixture(t)
	if r := fx.runApp(nil, "-no-such-flag"); r.code != 2 {
		t.Errorf("unknown flag: exit %d, want 2", r.code)
	}
	if r := fx.runApp(nil, "stray"); r.code != 2 {
		t.Errorf("positional argument: exit %d, want 2", r.code)
	}
	skipped := testCollector{"skipped", func(context.Context, *Env) ([]Finding, error) { return nil, ErrSkipped }}
	if r := fx.runApp([]Collector{skipped}); r.code != 0 {
		t.Errorf("skipped collector: exit %d, want 0", r.code)
	}
	partial := testCollector{"partial", func(context.Context, *Env) ([]Finding, error) { return nil, ErrPartial }}
	if r := fx.runApp([]Collector{partial}); r.code != 1 {
		t.Errorf("partial collector: exit %d, want 1", r.code)
	}

	bad := newFixture(t)
	bad.write(stateDirName, "not a directory")
	if r := bad.runApp(nil); r.code != 2 {
		t.Errorf("unusable state directory: exit %d, want 2", r.code)
	}
}

func TestSnapshotFilesNeverCollide(t *testing.T) {
	fx := newFixture(t)
	for range 3 {
		fx.runApp(nil) // same Env.Now, so the same second
	}
	if n := len(fx.historyFiles()); n != 3 {
		t.Errorf("%d snapshot files after 3 runs in one second", n)
	}
}
