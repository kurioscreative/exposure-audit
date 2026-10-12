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

var errDataless = errors.New("file contents are not local")

const defaultReadLimit = 2 << 20

// readFile reads at most limit bytes of a regular file, refusing files that
// are not local. Collectors read through this, never os.ReadFile, so no read
// can trigger an iCloud or file-provider download (invariant 2, A-29).
func readFile(p string, limit int64) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if isDataless(fi) {
		return nil, errDataless
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// tilde renders a path under the home as ~/rel. Locations are built from
// known paths like this, never from parsed content (A-26).
func (e *Env) tilde(p string) string {
	if rel, err := filepath.Rel(e.Home, p); err == nil && !strings.HasPrefix(rel, "..") {
		if rel == "." {
			return "~"
		}
		return "~/" + filepath.ToSlash(rel)
	}
	return p
}

// fileNotes are the prototype's per-file notes: stale static credentials and
// world- or group-readable files.
func (e *Env) fileNotes(p string, life Lifetime) []string {
	fi, err := os.Stat(p)
	if err != nil {
		return nil
	}
	var notes []string
	if days := int(e.Now.Sub(fi.ModTime()) / (24 * time.Hour)); days > 180 && life == Static {
		notes = append(notes, "unchanged for "+strconv.Itoa(days)+" days")
	}
	if fi.Mode().Perm()&0o044 != 0 {
		notes = append(notes, "readable by other local users")
	}
	return notes
}

// protectedDirs are TCC-protected folders. Listing one can raise the
// permission prompt that decision 17 makes opt-in, so walks never enter them
// unless -probe-folders is set or Full Disk Access is inferred yes (A-35).
var protectedDirs = []string{"Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Library/CloudStorage", "Pictures"}

// skipDirs are never descended by the sweep (prototype SKIP_DIRS).
var skipDirs = []string{"Library", "node_modules", ".git", ".Trash", "Pictures", "Music", "Movies", "Applications",
	".cache", ".npm", ".cargo", ".rustup", ".pyenv", ".nvm", "venv", ".venv", "__pycache__",
	"vendor", "Pods", "DerivedData", ".gradle", ".m2", "dist", "build", ".next", "target",
	".exposure-audit", ".docker", ".local", "go"}

type walkOpts struct {
	maxDepth      int
	allowProtect  bool // -probe-folders, or Full Disk Access inferred yes
	enterSkipDirs bool
}

// walk visits files under roots in sorted order, so a budget cut drops the
// same files each time. It returns ErrPartial when ctx ends first. fn gets
// the directory of each file too, so callers can look at siblings such as
// .git without walking into them.
func (e *Env) walk(ctx context.Context, roots []string, o walkOpts, fn func(dir string, d fs.DirEntry)) error {
	isProtected := func(p string) bool { return !o.allowProtect && e.underProtected(p) }
	var visit func(dir string, depth int) error
	visit = func(dir string, depth int) error {
		if ctx.Err() != nil {
			return ErrPartial
		}
		entries, err := os.ReadDir(dir) // sorted by name
		if err != nil {
			return nil // unreadable directories are simply not reachable
		}
		for _, d := range entries {
			if ctx.Err() != nil {
				return ErrPartial
			}
			p := filepath.Join(dir, d.Name())
			if d.IsDir() {
				if isProtected(p) || depth >= o.maxDepth || !o.enterSkipDirs && slices.Contains(skipDirs, d.Name()) {
					continue
				}
				if err := visit(p, depth+1); err != nil {
					return err
				}
				continue
			}
			if d.Type().IsRegular() {
				fn(dir, d)
			}
		}
		return nil
	}
	for _, r := range roots {
		if isProtected(r) {
			continue
		}
		if err := visit(r, 0); err != nil {
			return err
		}
	}
	return nil
}

// underProtected reports whether p is, or is inside, a TCC-protected folder.
func (e *Env) underProtected(p string) bool {
	for _, d := range protectedDirs {
		q := filepath.Join(e.Home, d)
		if p == q || strings.HasPrefix(p, q+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
