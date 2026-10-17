package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture is a fake home plus everything the tool would otherwise take from
// the real machine. Tests never exec the binary or touch the real home.
type fixture struct {
	t       *testing.T
	home    string
	root    string // stands in for "/" (Env.Root)
	environ map[string]Secret
	now     time.Time
	goos    string
	stubs   map[string]func(args []string) ([]byte, int) // by program path
	mu      sync.Mutex
	ran     []Cmd
	markers []string
}

func newFixture(t *testing.T) *fixture {
	return &fixture{
		t:       t,
		home:    t.TempDir(),
		root:    t.TempDir(),
		environ: map[string]Secret{},
		now:     time.Date(2026, 10, 12, 9, 30, 0, 0, time.UTC),
		goos:    "linux",
		stubs:   map[string]func([]string) ([]byte, int){},
	}
}

// write creates a file under the fake home, creating parent directories.
func (f *fixture) write(rel, content string) string {
	f.t.Helper()
	p := filepath.Join(f.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) setenv(name, value string) { f.environ[name] = NewSecret([]byte(value)) }

// secret returns a fixture secret: prefix + a unique high-entropy marker body
// of n characters, recorded so the leak test can look for it everywhere.
func (f *fixture) secret(prefix string, n int) string {
	body := randomAlnum(n)
	f.markers = append(f.markers, body)
	return prefix + body
}

func (f *fixture) env() *Env {
	return &Env{
		Home:    f.home,
		Root:    f.root,
		Environ: f.environ,
		GOOS:    f.goos,
		Now:     f.now,
		PID:     4242,
		Run:     guardRun(f.run),
		salt:    NewSecret([]byte("fixture-salt-0123456789abcdefghij")),
	}
}

func (f *fixture) run(_ context.Context, c Cmd) ([]byte, int, error) {
	f.mu.Lock()
	f.ran = append(f.ran, c)
	f.mu.Unlock()
	if stub, ok := f.stubs[c.Path]; ok {
		out, code := stub(c.Args)
		return out, code, nil
	}
	return nil, 1, nil
}

type result struct {
	stdout, stderr string
	code           int
}

// runApp runs the tool in-process against the fixture.
func (f *fixture) runApp(collectors []Collector, args ...string) result {
	f.t.Helper()
	var out, errb bytes.Buffer
	app := &App{Env: f.env(), Stdout: &out, Stderr: &errb, Collectors: collectors, Deadline: 5 * time.Second}
	code := app.Main(args)
	return result{out.String(), errb.String(), code}
}

// historyFiles returns the contents of every snapshot written so far.
func (f *fixture) historyFiles() []string {
	f.t.Helper()
	var out []string
	matches, _ := filepath.Glob(filepath.Join(f.home, stateDirName, "history", "*.json"))
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			f.t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

// assertNoMarkers fails if any fixture secret appears in any output.
func (f *fixture) assertNoMarkers(outputs ...string) {
	f.t.Helper()
	all := append(outputs, f.historyFiles()...)
	for _, m := range f.markers {
		for _, o := range all {
			if strings.Contains(o, m) {
				f.t.Errorf("secret marker %.6s... leaked into output", m)
			}
		}
	}
}

type fileState struct {
	mode fs.FileMode
	size int64
	mod  time.Time
}

// tree records every path under root with its mode, size and mtime.
func tree(t *testing.T, root string) map[string]fileState {
	t.Helper()
	m := map[string]fileState{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		fi, err := d.Info()
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, p)
		m[rel] = fileState{fi.Mode(), fi.Size(), fi.ModTime()}
		return nil
	})
	return m
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomAlnum(n int) string {
	b := make([]byte, n)
	r := make([]byte, n)
	rand.Read(r)
	for i := range b {
		b[i] = alnum[int(r[i])%len(alnum)]
	}
	return string(b)
}

func decodeSnapshot(t *testing.T, s string) Snapshot {
	t.Helper()
	var snap Snapshot
	if err := json.Unmarshal([]byte(s), &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	// Two findings with one ID are two things the diff and Fix first cannot
	// tell apart (A-59, A-60).
	ids := map[string]bool{}
	for _, f := range snap.Findings {
		if ids[f.ID] {
			t.Errorf("duplicate finding ID %s at %s", f.ID, f.Location)
		}
		ids[f.ID] = true
	}
	return snap
}
