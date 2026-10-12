package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const stateDirName = ".exposure-audit"

// prepareStateDir creates ~/.exposure-audit and its history directory with
// mode 0700 (invariant 3) and deletes a report.html left by an interrupted
// -open run (decision 15).
func prepareStateDir(home string) (string, error) {
	dir := filepath.Join(home, stateDirName)
	for _, d := range []string{dir, filepath.Join(dir, "history")} {
		if err := os.Mkdir(d, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		// Lstat so a symlink planted in place of the directory is refused.
		fi, err := os.Lstat(d)
		if err != nil {
			return "", err
		}
		if !fi.IsDir() {
			return "", errors.New("state path is not a directory")
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return "", err
		}
	}
	if err := os.Remove(filepath.Join(dir, "report.html")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return dir, nil
}

// writeSnapshotFile writes history/<stamp>.json with O_EXCL, appending -2,
// -3, ... on collision so two runs in one second never overwrite (A-30).
func writeSnapshotFile(stateDir, stamp string, b []byte) (string, error) {
	for n := 1; ; n++ {
		name := stamp + ".json"
		if n > 1 {
			name = fmt.Sprintf("%s-%d.json", stamp, n)
		}
		p := filepath.Join(stateDir, "history", name)
		err := writeExclusive(p, b)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return p, err
	}
}
