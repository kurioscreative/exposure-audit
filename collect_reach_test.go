package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Permission-denied cases cannot be built as root (the Linux container runs
// tests as root, and root reads mode-000 directories).
func skipIfRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
}

func TestInferFullDiskAccess(t *testing.T) {
	fx := newFixture(t)
	fx.write("Library/Mail/V10/x", "mail")
	if got := inferFullDiskAccess(fx.env()); got != "unknown" {
		t.Errorf("non-darwin: %q, want unknown", got)
	}
	fx.goos = "darwin"
	if got := inferFullDiskAccess(fx.env()); got != "yes" {
		t.Errorf("readable Mail: %q, want yes", got)
	}

	empty := newFixture(t)
	empty.goos = "darwin"
	if got := inferFullDiskAccess(empty.env()); got != "unknown" {
		t.Errorf("no probe folders: %q, want unknown", got)
	}
}

func TestInferFullDiskAccessDenied(t *testing.T) {
	skipIfRoot(t)
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Messages/chat.db", "x")
	dir := filepath.Join(fx.home, "Library/Messages")
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if got := inferFullDiskAccess(fx.env()); got != "no" {
		t.Errorf("all existing denied: %q, want no", got)
	}
}

func reachRows(t *testing.T, fx *fixture, opts Options, fda string) ([]ReachRow, error) {
	t.Helper()
	c := newReachCollectors(opts, fda)[0].(*reachCollector)
	_, err := c.Collect(context.Background(), fx.env())
	var s Snapshot
	c.Section(&s)
	return s.Reach, err
}

func rowFor(rows []ReachRow, label string) *ReachRow {
	for i := range rows {
		if rows[i].Label == label {
			return &rows[i]
		}
	}
	return nil
}

func TestReachMeasuresAndRespectsProtectedFolders(t *testing.T) {
	fx := newFixture(t)
	fx.write("Library/Application Support/Google/Chrome/Default/History", "0123456789")
	fx.write("Library/Application Support/Google/Chrome/Local State", "abc")
	fx.write("Documents/notes.txt", "private")

	if _, err := reachRows(t, fx, Options{}, "unknown"); err != ErrSkipped {
		t.Errorf("non-darwin: err %v, want ErrSkipped", err)
	}
	fx.goos = "darwin"
	rows, err := reachRows(t, fx, Options{}, "unknown")
	if err != nil {
		t.Fatal(err)
	}
	chrome := rowFor(rows, "Chrome profile")
	if chrome == nil || chrome.Status != "readable" || chrome.Files != 2 || chrome.Bytes != 13 || chrome.Partial {
		t.Errorf("chrome row %+v", chrome)
	}
	if chrome != nil && chrome.Path != "~/Library/Application Support/Google/Chrome" {
		t.Errorf("chrome path %q", chrome.Path)
	}
	if d := rowFor(rows, "Documents"); d == nil || d.Status != "not probed" || d.Files != 0 {
		t.Errorf("Documents without -probe-folders: %+v", d)
	}
	if rowFor(rows, "Firefox profiles") != nil {
		t.Error("missing app folder listed")
	}

	for _, c := range []struct {
		opts Options
		fda  string
	}{{Options{ProbeFolders: true}, "unknown"}, {Options{}, "yes"}} {
		rows, _ = reachRows(t, fx, c.opts, c.fda)
		if d := rowFor(rows, "Documents"); d == nil || d.Status != "readable" || d.Files != 1 {
			t.Errorf("Documents with %+v fda=%s: %+v", c.opts, c.fda, d)
		}
	}
}

func TestReachBudgetMarksPartial(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Application Support/Slack/a", "x")
	c := &reachCollector{budget: 0}
	if _, err := c.Collect(context.Background(), fx.env()); err != nil {
		t.Fatal(err)
	}
	if r := rowFor(c.rows, "Slack data"); r == nil || !r.Partial {
		t.Errorf("zero budget: %+v, want partial", r)
	}
}

func TestReachBlockedFolder(t *testing.T) {
	skipIfRoot(t)
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Safari/History.db", "x")
	dir := filepath.Join(fx.home, "Library/Safari")
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	rows, _ := reachRows(t, fx, Options{}, "no")
	if r := rowFor(rows, "Safari data"); r == nil || r.Status != "blocked" {
		t.Errorf("Safari row %+v, want blocked", r)
	}
}

// §11 "Full Disk Access": a readable Library/Mail pins a tier-0 item on top
// and leaves the total unchanged (decision 12).
func TestFullDiskAccessPinnedItem(t *testing.T) {
	fx := newFixture(t)
	fx.goos = "darwin"
	fx.setenv("__CFBundleIdentifier", "com.example.term")
	fx.write("Library/Mail/V10/x", "mail")
	npm := fnd("npm-token", "~/.npmrc", Propagation, "npm1")
	cs := append([]Collector{staticCollector("files", nil, npm)}, newReachCollectors(Options{}, "yes")...)
	snap, code := fx.runJSON(cs)
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	if snap.FullDiskAccess != "yes" || snap.Total != 10 {
		t.Errorf("fda %q total %v; want yes and 10", snap.FullDiskAccess, snap.Total)
	}
	if len(snap.Items) != 2 || snap.Items[0].Tier != 0 || snap.Items[0].Title != "Full Disk Access granted to com.example.term" || snap.Items[0].Score != 0 {
		t.Errorf("items %+v; want the pinned tier-0 item first", snap.Items)
	}
	if r := rowFor(snap.Reach, "Mail"); r == nil || r.Status != "readable" {
		t.Errorf("Mail reach row %+v", r)
	}
	r := fx.runApp(cs)
	if !strings.Contains(r.stdout, "1. [pinned] Full Disk Access granted to com.example.term") {
		t.Errorf("summary lacks the pinned item:\n%s", r.stdout)
	}
	fx.assertNoMarkers(r.stdout, r.stderr)
}
