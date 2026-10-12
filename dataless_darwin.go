package main

import (
	"io/fs"
	"syscall"
)

// sfDataless marks a file whose contents iCloud or a file provider has
// evicted. Reading it triggers a download (A-29).
const sfDataless = 0x40000000

func isDataless(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}
