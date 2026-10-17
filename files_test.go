package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWalkIsSortedAndSkipsProtectedAndSkipDirs(t *testing.T) {
	fx := newFixture(t)
	for _, p := range []string{"b/.env", "a/.env", "a/node_modules/x/.env", "Documents/app/.env", "a/b/c/d/.env"} {
		fx.write(p, "x")
	}
	env := fx.env()
	env.realHome, _ = filepath.EvalSymlinks(fx.home) // as Main sets it
	collect := func(o walkOpts, roots ...string) ([]string, error) {
		var got []string
		err := env.walk(context.Background(), roots, o, func(dir string, d fs.DirEntry) {
			got = append(got, env.tilde(filepath.Join(dir, d.Name())))
		})
		return got, err
	}
	got, err := collect(walkOpts{maxDepth: 5}, fx.home)
	want := []string{"~/a/.env", "~/a/b/c/d/.env", "~/b/.env"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %v %v, want %v", got, err, want)
	}
	got, _ = collect(walkOpts{maxDepth: 5, allowProtect: true}, fx.home)
	if !slices.Contains(got, "~/Documents/app/.env") {
		t.Errorf("allowProtect did not enter Documents: %v", got)
	}
	got, _ = collect(walkOpts{maxDepth: 5}, filepath.Join(fx.home, "Documents", "app"))
	if len(got) != 0 {
		t.Errorf("a root inside a protected folder was walked: %v", got)
	}
	link := filepath.Join(fx.home, "link")
	if err := os.Symlink(filepath.Join(fx.home, "Documents", "app"), link); err != nil {
		t.Fatal(err)
	}
	got, _ = collect(walkOpts{maxDepth: 5}, link)
	if len(got) != 0 {
		t.Errorf("a root symlinked into a protected folder was walked: %v", got)
	}
	got, _ = collect(walkOpts{maxDepth: 5, allowProtect: true}, link)
	if len(got) != 1 {
		t.Errorf("allowProtect did not walk the symlinked root: %v", got)
	}
	got, _ = collect(walkOpts{maxDepth: 2}, fx.home)
	if slices.Contains(got, "~/a/b/c/d/.env") {
		t.Errorf("maxDepth ignored: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := env.walk(ctx, []string{fx.home}, walkOpts{maxDepth: 5}, func(string, fs.DirEntry) {}); err != ErrPartial {
		t.Errorf("expired budget: err %v, want ErrPartial", err)
	}
}

// A dotfile symlinked into a protected folder, and a worktree whose gitdir
// points into one, are not read unless -probe-folders is given (decision 17).
func TestReadsNeverResolveIntoProtectedFolders(t *testing.T) {
	fx := newFixture(t)
	tok := fx.secret("sk-proj-", 40)
	ghp := fx.secret("ghp_", 36)
	fx.write("Documents/dotfiles/zshrc", "export OPENAI_API_KEY="+tok+"\n")
	if err := os.Symlink(filepath.Join(fx.home, "Documents/dotfiles/zshrc"), filepath.Join(fx.home, ".zshrc")); err != nil {
		t.Fatal(err)
	}
	fx.write("Documents/repo/.git/config", "[remote \"origin\"]\n\turl = https://x:"+ghp+"@github.com/o/r.git\n")
	fx.write("Documents/repo/.git/worktrees/wt/commondir", "../..\n")
	fx.write("code/wt/.git", "gitdir: "+filepath.Join(fx.home, "Documents/repo/.git/worktrees/wt")+"\n")
	fx.write("code/wt/.env", "X=1\n")

	s, _ := fx.runJSON(nil)
	if s.Total != 0 || len(s.Findings) != 0 {
		t.Errorf("default run read into Documents: total %v, findings %+v", s.Total, s.Findings)
	}
	s, _ = fx.runJSON(nil, "-probe-folders")
	if s.Total != 15 {
		t.Errorf("with -probe-folders: total %v, want 15 (service 5 + propagation 10)", s.Total)
	}
	fx.assertNoMarkers()
}
