//go:build !darwin

package main

import "io/fs"

// Only macOS has dataless files; see dataless_darwin.go.
func isDataless(fs.FileInfo) bool { return false }
