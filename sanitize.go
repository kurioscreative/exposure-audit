package main

import "fmt"

// sanitizeKeychainSample implements -sanitize-keychain-sample. Implemented in M2.
func (a *App) sanitizeKeychainSample() int {
	fmt.Fprintln(a.Stderr, "exposure-audit: -sanitize-keychain-sample is not implemented yet")
	return 2
}
