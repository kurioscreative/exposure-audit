package main

import (
	"context"
	"io/fs"
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
