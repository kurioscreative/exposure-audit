package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Whether a file is tracked by git, read from the repository's .git/index
// directly: running git is not allowed (invariant 8). Decision 9 uses this to
// score committed dotenv files lower.

var errBadIndex = errors.New("unparseable git index")

// gitIndexLimit bounds the read of one index; a larger index is truncated,
// fails to parse, and the file counts as not committed at medium confidence.
const gitIndexLimit = 64 << 20

// gitRepos caches parsed indexes per repository root for one sweep.
type gitRepos struct {
	env    *Env
	byRoot map[string]map[string]bool // root → tracked paths; nil value if unparseable
}

// repoRoot returns the nearest ancestor of dir (inclusive) that contains .git.
func repoRoot(dir string) (string, bool) {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// gitDir resolves root/.git. In a worktree, .git is a file holding
// "gitdir: <path>", and that directory holds the worktree's own index.
func gitDir(env *Env, root string) (string, error) {
	p := filepath.Join(root, ".git")
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return p, nil
	}
	b, err := env.readFile(p, 4096)
	if err != nil {
		return "", err
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return "", errBadIndex
	}
	d := strings.TrimSpace(rest)
	if !filepath.IsAbs(d) {
		d = filepath.Join(root, d)
	}
	return filepath.Clean(d), nil
}

// gitConfigPath is the config shared by a repository and its worktrees: a
// worktree's gitdir names the main repository's through its commondir file.
func gitConfigPath(env *Env, gd string) string {
	if b, err := env.readFile(filepath.Join(gd, "commondir"), 4096); err == nil {
		c := strings.TrimSpace(string(b))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gd, c)
		}
		return filepath.Join(filepath.Clean(c), "config")
	}
	return filepath.Join(gd, "config")
}

// tracked reports whether path is in its repository's index. known is false
// when the file is in a repository whose index could not be read or parsed.
func (g *gitRepos) tracked(path string) (tracked, known bool) {
	root, ok := repoRoot(filepath.Dir(path))
	if !ok {
		return false, true
	}
	if g.byRoot == nil {
		g.byRoot = map[string]map[string]bool{}
	}
	paths, ok := g.byRoot[root]
	if !ok {
		if gd, err := gitDir(g.env, root); err == nil {
			if b, err := g.env.readFile(filepath.Join(gd, "index"), gitIndexLimit); err == nil {
				paths, _ = parseGitIndex(b)
			}
		}
		g.byRoot[root] = paths
	}
	if paths == nil {
		return false, false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false, false
	}
	return paths[filepath.ToSlash(rel)], true
}

// parseGitIndex returns the paths in a version 2, 3 or 4 index. Versions 2
// and 3 store each path whole, NUL-terminated, with the entry padded to a
// multiple of 8 bytes. Version 4 prefix-compresses each path against the
// previous one and has no padding.
// Format: https://git-scm.com/docs/index-format
func parseGitIndex(b []byte) (map[string]bool, error) {
	if len(b) < 12 || string(b[:4]) != "DIRC" {
		return nil, errBadIndex
	}
	ver := binary.BigEndian.Uint32(b[4:8])
	n := binary.BigEndian.Uint32(b[8:12])
	if ver < 2 || ver > 4 {
		return nil, errBadIndex
	}
	const fixed = 62 // stat data (40) + object id (20) + flags (2)
	paths := map[string]bool{}
	off, prev := 12, ""
	for range n {
		start := off
		if off+fixed > len(b) {
			return nil, errBadIndex
		}
		flags := binary.BigEndian.Uint16(b[off+60:])
		off += fixed
		if ver >= 3 && flags&0x4000 != 0 { // extended flags
			off += 2
		}
		if off > len(b) {
			return nil, errBadIndex
		}
		var path string
		if ver == 4 {
			strip, k := gitVarint(b[off:])
			if k == 0 || strip > len(prev) {
				return nil, errBadIndex
			}
			off += k
			end := bytes.IndexByte(b[off:], 0)
			if end < 0 {
				return nil, errBadIndex
			}
			path = prev[:len(prev)-strip] + string(b[off:off+end])
			off += end + 1
		} else {
			end := bytes.IndexByte(b[off:], 0)
			if end < 0 {
				return nil, errBadIndex
			}
			path = string(b[off : off+end])
			off = start + (off+end-start+8)&^7
		}
		paths[path] = true
		prev = path
	}
	return paths, nil
}

// gitVarint decodes git's offset varint (varint.c). It returns the value and
// the number of bytes read, or 0 bytes on malformed input.
func gitVarint(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	val, i := int(c&127), 1
	for c&128 != 0 {
		if i >= len(b) || val > 1<<24 {
			return 0, 0
		}
		c = b[i]
		i++
		val = ((val + 1) << 7) + int(c&127)
	}
	return val, i
}
