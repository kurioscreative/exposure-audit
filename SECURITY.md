# Security policy

exposure-audit reads credential files and Keychain access lists on your machine, so a bug that leaks a secret value, writes outside `~/.exposure-audit`, runs an unexpected program or touches the network is a security issue.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/kurioscreative/exposure-audit/security/advisories/new). Please do not open a public issue.

Include the steps to reproduce and the macOS and Go versions. Never include a real report, snapshot, secret or path listing from your machine: describe the shape of the file or environment instead, with fake values.

## Supported versions

Only the latest commit on `main` is supported.
