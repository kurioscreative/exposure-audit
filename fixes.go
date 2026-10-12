package main

// Fix texts, keyed by finding family (prototype FIX, plus decision 11 and 12).
var fixText = map[string]string{
	"npm":         "Publish with npm trusted publishing (OIDC) so no token lives on disk; if you must keep one, make it granular, read-only, and short-lived. Set ignore-scripts=true.",
	"registry":    "Use the registry's trusted-publisher (OIDC) flow from CI and delete the local upload token.",
	"github":      "Keep the token in the Keychain behind an app-gated helper, or use a fine-grained token with minimal repo scope and an expiry. Remove plaintext copies.",
	"ssh-plain":   "Move this key into the Secure Enclave (Secretive) or a password-manager SSH agent that asks per use. At minimum add a passphrase.",
	"ssh-agent":   "Use an agent that requires approval per signature (Secretive, 1Password) so a background script cannot use loaded keys.",
	"aws-static":  "Replace static keys with IAM Identity Center (aws sso login) or aws-vault, then delete the key in IAM.",
	"aws-session": "Already short-lived. Shorten the session duration if you can, and avoid caching admin roles.",
	"cloud":       "Switch to short-lived, browser-brokered login and revoke the stored long-lived credential.",
	"kube":        "Use an exec credential plugin (cloud CLI or OIDC) instead of an embedded token or client key.",
	"docker":      "Set credsStore to osxkeychain and remove inline auth entries. Note any process can still ask the helper.",
	"file-token":  "Revoke and reissue this token with the narrowest scope and an expiry; inject it per command (op run, or a Keychain lookup) instead of leaving it on disk.",
	"env":         "Do not export secrets in your shell session. Inject them only into the one command that needs them (op run -- cmd).",
	"rc":          "Remove the literal from your shell startup file and rotate it. Fetch it at call time from a password manager.",
	"history":     "Rotate anything listed, then purge the entries. In zsh set HIST_IGNORE_SPACE and prefix sensitive commands with a space.",
	"dotenv":      "Replace values with password-manager references (op run with .env templates) or a per-project secrets tool, and rotate what was exposed.",
	"ai":          "Move keys out of the config: reference an environment variable injected at launch, or use the tool's OAuth login. Rotate the key.",
	"keychain":    "Tighten the item's access list so only the owning app can read it (Keychain Access > item > Access Control), or move it to a manager that asks per use.",
	"agent":       "Coding-agent sessions pass this token to every command they run, including package installs. Find out what it authorizes, and run installs from a plain terminal or a sandbox.",
}
