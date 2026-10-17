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

var errProtected = errors.New("path is in a protected folder")

// readFile reads at most limit bytes of a regular file, refusing files that
// are not local and, unless allowed, files that resolve into a TCC-protected
// folder. Collectors read through this, never os.ReadFile, so no read can
// trigger an iCloud or file-provider download (invariant 2, A-29) or a
// folder prompt (decision 17): dotfile managers often symlink ~/.zshrc into
// ~/Documents or iCloud Drive, and worktree gitdir files can point there.
func (e *Env) readFile(p string, limit int64) ([]byte, error) {
	if !e.allowProtected && e.resolvesIntoProtected(p) {
		return nil, errProtected
	}
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
		if fi, err := os.Lstat(dir); err != nil || isDataless(fi) {
			return nil // an evicted directory: listing it would download it (A-29)
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
		if !o.allowProtect && e.resolvesIntoProtected(r) {
			continue // the root itself may be a symlink into a protected folder
		}
		if err := visit(r, 0); err != nil {
			return err
		}
	}
	return nil
}

// underProtected reports whether p is, or is inside, a TCC-protected folder.
func (e *Env) underProtected(p string) bool {
	for _, home := range []string{e.Home, e.realHome} {
		if home == "" {
			continue
		}
		for _, d := range protectedDirs {
			q := filepath.Join(home, d)
			if p == q || strings.HasPrefix(p, q+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// resolvesIntoProtected follows symlinks in p one component at a time with
// lstat and readlink, stopping before it would touch anything inside a
// protected folder. filepath.EvalSymlinks would lstat inside the target.
func (e *Env) resolvesIntoProtected(p string) bool {
	for hops := 0; hops < 16; hops++ {
		parts := strings.Split(filepath.Clean(p), string(filepath.Separator))
		cur, next := string(filepath.Separator), ""
		for i, part := range parts {
			if part == "" {
				continue
			}
			cur = filepath.Join(cur, part)
			if e.underProtected(cur) {
				return true
			}
			fi, err := os.Lstat(cur)
			if err != nil {
				return false // missing: the read fails on its own
			}
			if fi.Mode()&fs.ModeSymlink != 0 {
				t, err := os.Readlink(cur)
				if err != nil {
					return false
				}
				if !filepath.IsAbs(t) {
					t = filepath.Join(filepath.Dir(cur), t)
				}
				next = filepath.Join(append([]string{t}, parts[i+1:]...)...)
				break
			}
		}
		if next == "" {
			return false
		}
		p = next
	}
	return true // a symlink loop or a very long chain: refuse
}
