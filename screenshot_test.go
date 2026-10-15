package main

// Renders the README screenshots' source from a fake home. Skipped unless
// SCREENSHOT_OUT is set; docs/screenshots.sh runs it and takes the pictures.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScreenshotFixture(t *testing.T) {
	out := os.Getenv("SCREENSHOT_OUT")
	if out == "" {
		t.Skip("SCREENSHOT_OUT not set")
	}
	dump := readTestdata(t, "keychain_section12.txt")
	fx := baseFixture(t)
	fx.goos = "darwin"
	fx.write("Library/Keychains/login.keychain-db", "")
	fx.stubs["/usr/bin/security"] = func([]string) ([]byte, int) { return []byte(dump), 0 }
	fx.stubs["/bin/ps"] = func(args []string) ([]byte, int) {
		chain := map[string]string{"4242": "4100 exposure-audit", "4100": "4000 -zsh", "4000": "1 iTerm2"}
		return []byte(chain[args[len(args)-1]]), 0
	}
	fx.setenv("TERM_PROGRAM", "iTerm.app")
	fx.setenv("USER", "demo")
	// Sparse files: realistic sizes in Data reach without writing gigabytes.
	for rel, size := range map[string]int64{
		"Documents/taxes-2025.pdf": 4 << 20, "Documents/contracts/lease.pdf": 2 << 20, "Documents/photos.zip": 3 << 30,
		"Downloads/installer.dmg": 900 << 20, "Downloads/report.csv": 12 << 20, "Desktop/screenshot.png": 3 << 20,
		"Library/Application Support/Google/Chrome/Default/Cookies":    6 << 20,
		"Library/Application Support/Google/Chrome/Default/Login Data": 1 << 20,
		"Library/Application Support/Slack/storage/root-state.json":    40 << 20,
	} {
		if err := os.Truncate(fx.write(rel, ""), size); err != nil {
			t.Fatal(err)
		}
	}
	// A folder the terminal is denied, so Full Disk Access is inferred "no".
	mail := filepath.Join(fx.home, "Library/Mail")
	fx.write("Library/Mail/V10/x", "")
	os.Chmod(mail, 0)
	t.Cleanup(func() { os.Chmod(mail, 0o755) })

	run := func(args ...string) string {
		var o, e bytes.Buffer
		fx.now = fx.now.Add(time.Second)
		app := &App{Env: fx.env(), Stdout: &o, Stderr: &e, Deadline: 5 * time.Second}
		if code := app.Main(append(args, "-probe-folders")); code != 0 {
			t.Fatalf("exit %d: %s", code, e.String())
		}
		return o.String()
	}
	run()
	// A day later: the npm token was rotated and the Cursor MCP token removed.
	fx.now = fx.now.Add(26 * time.Hour)
	fx.write(".npmrc", "//registry.npmjs.org/:_authToken="+fx.secret("npm_", 36)+"\n")
	if err := removeFile(fx, ".cursor/mcp.json"); err != nil {
		t.Fatal(err)
	}
	summary := run()
	// Drop that run's snapshot so the -open run also diffs against the first.
	hist, _ := filepath.Glob(filepath.Join(fx.home, stateDirName, "history", "*.json"))
	os.Remove(hist[len(hist)-1])

	var report []byte
	fx.stubs["/usr/bin/open"] = func(args []string) ([]byte, int) {
		report, _ = os.ReadFile(args[0]) // read before openReport deletes it
		return nil, 0
	}
	run("-open")

	fx.assertNoMarkers(summary, string(report))
	for name, b := range map[string][]byte{"report.html": report, "summary.txt": []byte(summary)} {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
