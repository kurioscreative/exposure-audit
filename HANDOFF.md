# Exposure Audit (Go): agent handoff

You are starting a new Go implementation. There is no repository yet. A Python prototype, `exposure_audit.py` (v0.1.0, 990 lines, sha256 prefix `b2a9b3a3434feec9`), accompanies this document. Treat it as a behavioral reference and a source of data tables, not as code to extend. It has known design defects (section 7) that the Go version fixes by design instead of porting.

## 1. What we are building and why

A local macOS utility that answers one question:

> Show me, in under a minute and fully offline, everything a malicious install script launched from my terminal could silently read or use, ranked by blast radius, so I know what to fix first.

The reference threat is the Shai-Hulud npm worm family (2025). What matters about it here: it ran as the logged-in user inside a package install hook, needed no root and no exploit, harvested developer credentials from well-known files and environment variables (it ran TruffleHog to find more), and used stolen npm and GitHub tokens to republish itself. Later variants reportedly ran at preinstall and could destroy the home directory. These details are from memory; check the references in section 13 before relying on any specific one.

The consequence for design: the tool must measure from the attacker's exact position. Same user, same inherited permissions, no elevation. The valuable output is not "how many secrets exist" but "which few long-lived credentials give an attacker the most reach, and what replaces each one".

### Done means

| Property   | Meaning                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------- |
| Faithful   | Measures what a child process of the launching terminal can reach, not a theoretical maximum |
| Safe       | No secret value is ever printed, logged, or stored. Nothing leaves the machine               |
| Ranked     | A short prioritized list, not a dump                                                         |
| Actionable | Every finding names its fix                                                                  |
| Repeatable | Stable fingerprints and history, so the score can be driven down over time                   |

### Non-goals

- Detecting an existing infection (indicator scanning is a different tool).
- Blocking or sandboxing installs.
- Fleet or team management.
- Windows or Linux as targets. Linux matters only because that is where agents build and test.

## 2. Decisions already made

Do not reopen these without asking Glenn.

1. **Scope:** credentials are scored. Other data (Documents, iCloud, Mail, browser profiles) gets a coarse reach check with sizes and is not scored.
2. **Audience:** Glenn only for now, built so it could be shared later.
3. **Depth:** offline inventory. Checking whether a token is live or what it is scoped to needs network calls and is a possible later opt-in mode.
4. **Tracking:** salted fingerprints and run history from the start.
5. **Language:** Go, standard library only, no cgo, one static binary. Chosen over Python (not on a stock Mac, interpreter is attack surface), Swift (agents cannot build or test Apple-framework code on Linux), Rust (needs crates for hashing, JSON, and regex), Bash (unsafe secret handling), and Ruby (deprecated on macOS).

One accepted cost of decision 5: no native Keychain API access. Keychain analysis parses the output of `/usr/bin/security`. If macOS validation (milestone M5) shows that parsing is too fragile, raise it with Glenn; do not reach for cgo on your own.

## 3. Invariants

Every change must preserve these. Section 6 says how each is enforced mechanically.

1. **No secret values at rest or on screen.** Values are read into memory, fingerprinted, and dropped. This covers the report, history, stdout, stderr, error strings, panics, and test logs.
2. **No network.** The binary must not link the `net` or `net/http` packages, and must not run a subprocess that makes network calls.
3. **Read-only outside `~/.exposure-audit`.** That directory is 0700; files in it are 0600.
4. **Standard library only.** `go.mod` has no `require` lines and there is no `go.sum`. `CGO_ENABLED=0`.
5. **Unprivileged.** No sudo, no entitlements, no app bundle with its own permissions. Any of these would measure the wrong position.
6. **A broken collector must not sink the run.** Collector errors and panics are contained and reported; the report still renders.
7. **Never read a Keychain item's value.** Access-list metadata only. `security dump-keychain` is called with `-a` and never `-d`.
8. **Subprocesses run by absolute path.** `/usr/bin/security`, `/usr/bin/ssh-add`, `/bin/ps`. A tool that resolves helpers through `PATH` can be hijacked by the very thing it audits. Where a helper has no fixed system path (workstream M4), resolve it once, record the resolved path in the finding, and never go through a shell.

## 4. Rules for agents

- **Never run the tool against a real home directory**, including Glenn's linked Mac, unless he explicitly asks in that session. Tests use `t.TempDir()` homes.
- **Never paste a report, snapshot, or real path listing into a conversation or commit.** The report is a map of where secrets live. The terminal summary (titles, paths, scores) is the only thing Glenn has agreed to share back.
- **Build fake tokens at runtime.** Fixtures need strings that match real token formats. Committing them as literals trips secret scanners and push protection. Assemble them by concatenation in test helpers.
- **Report honestly.** If something is unverified on macOS, say so in a code comment and in your handback. Most of this project's risk sits in macOS behavior nobody has observed yet.
- **Ask before:** changing score weights, adding any network path, adding a dependency, enabling cgo, or changing an invariant.

## 5. Architecture

### Layout

```
go.mod                      module exposure-audit, no requires
main.go                     flags, orchestration, exit codes
model.go                    Finding, Snapshot, Secret, enums
score.go                    scoring and ranking
fingerprint.go              salt handling, HMAC
env.go                      Env abstraction (below)
state.go                    state directory, history, diff
match.go                    token patterns and the generic matcher
collect_files.go            table-driven known credential files
collect_aws.go
collect_ssh.go
collect_ambient.go          environment, shell files, history, dotenv sweep
collect_keychain.go         dump parser and classifier
collect_ai.go
collect_helpers.go          usable authority through helper programs (M4)
collect_reach.go            context, Full Disk Access probe, data reach
report.go                   html/template, CSS embedded
*_test.go
testdata/                   sanitized samples only; no real output
prototype/exposure_audit.py reference only
HANDOFF.md
```

One `main` package is fine at this size. Split into internal packages only if it clearly helps.

### The Env abstraction

Collectors never call `os.Getenv`, `os.UserHomeDir`, `exec.Command`, or `time.Now` directly. They receive an `Env`:

```go
type Env struct {
    Home    string
    Environ map[string]string
    GOOS    string
    Now     time.Time
    Run     func(ctx context.Context, path string, args ...string) (stdout []byte, exit int, err error)
}

type Collector interface {
    Name() string
    Collect(ctx context.Context, env *Env) ([]Finding, error)
}
```

This is what makes every collector testable on Linux: tests pass a temp home, a fake environment, and a stub `Run` that returns canned output (for example a sample Keychain dump). It also gives one place to enforce invariant 8.

Collectors run concurrently under a shared deadline. Each is wrapped so that an error or panic becomes an entry in `Snapshot.Errors` holding only the collector name and a fixed category string. Never store `err.Error()`: some standard library errors quote their input (`strconv` does), which could be a secret.

### The Secret type

Raw values must be hard to leak by accident:

```go
type Secret struct{ b []byte }
func (Secret) String() string                 { return "[redacted]" }
func (Secret) GoString() string               { return "[redacted]" }
func (Secret) Format(f fmt.State, c rune)     { io.WriteString(f, "[redacted]") }
func (Secret) MarshalJSON() ([]byte, error)   { return nil, errors.New("secret is not serializable") }
func (s Secret) Fingerprint(salt []byte) string
```

The matcher and collectors pass `Secret` values, never `string`. The only way out of a `Secret` is `Fingerprint`. `Finding` has no field that can hold one.

### Data model

`Finding`: `ID, Layer, Kind, Title, Location, Class, Count, Lifetime, Gate, Detail, Notes, Confidence, Fix, Fingerprints, Score`.

- `Class`: `propagation` (npm, GitHub, registries, SSH: makes the victim a worm vector), `cloud`, `service`, `generic`.
- `Gate`: `silent` or `gated` (needs a passphrase, touch, or approval).
- `Lifetime`: `static` or `session`.
- `Fingerprint`: `hex(HMAC-SHA256(salt, value))[:12]`. Salt is 32 random bytes in `~/.exposure-audit/salt`.
- `SlotID`: `sha256(kind | location)[:12]`. Identifies where a credential lives.
- `ID`: `sha256(kind | location | sorted fingerprints)[:12]`. Identifies a specific credential in that place.

Two ids let the diff tell "rotated" (same slot, different id) from "resolved" and "new". The prototype has only `ID` and cannot.

There is no compatibility requirement with the prototype's snapshot format. Glenn has no history to preserve. Version the snapshot schema from 1.

### Scoring

Carry this over unchanged. The weights are a first guess that Glenn has not yet reviewed against real output.

```
score = BASE[class] * (0.4 if session) * (0.1 if gated) * (1 + min(n - 1, 4) * 0.25)
BASE  = propagation 10, cloud 8, service 5, generic 3
total = sum of finding scores, rounded to one decimal
```

### State on disk

```
~/.exposure-audit/
  salt                              32 bytes, 0600
  report.html                       overwritten each run
  history/YYYYMMDD-HHMMSS.json      one snapshot per run
```

Each snapshot records a **context key**: the launching application (from the parent process chain) plus the Full Disk Access result. Diffs compare only against the most recent snapshot with the same context key. The tool is meant to be run from several terminals, and the prototype's context-blind diff produces spurious churn between them.

### Command line

`exposure-audit [-open] [-json] [-no-folder-probe] [-skip-keychain] [-roots dir,dir] [-max-depth N]`. Default output is the short terminal summary plus the path to the report.

## 6. Enforcing the invariants

These tests are part of M0 and must exist before any collector is written.

| Invariant                 | Mechanical check                                                                                                                                                                                                                                                             |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No secret values          | Leak test: every fixture secret carries a unique marker; run the full tool; assert no marker in stdout, stderr, `report.html`, or any history file. Also a unit test that `fmt.Sprintf` with `%v`, `%+v`, `%#v`, `%s` and `json.Marshal` on a `Secret` never yield the value |
| No network                | `go list -deps .` must not contain `net` or `net/http`. If a standard library package you want pulls one in, find another way or ask                                                                                                                                         |
| Standard library only     | Test parses `go.mod` and fails on any `require`; fails if `go.sum` exists; build with `CGO_ENABLED=0`                                                                                                                                                                        |
| Read-only, permissions    | Test snapshots the fixture home's file list and modes before and after a run; only `.exposure-audit` may differ, with 0700 and 0600                                                                                                                                          |
| Collector containment     | Test registers a collector that panics and one that errors; report still renders; `Errors` holds two entries with no dynamic text                                                                                                                                            |
| Absolute subprocess paths | Test wraps `Env.Run` and fails on any non-absolute path or any call to a shell                                                                                                                                                                                               |

Also run `go vet` and `gofmt -l` in the test script. The whole suite should finish in under 30 seconds on Linux.

## 7. What to take from the prototype, and what not to

### Take

- **Data tables.** `SPECS` (about 30 credential files with capture patterns), `TOKEN_RX`, `REACH_TARGETS`, `AI_FILES`, `FIX` texts, `SKIP_DIRS`. Transcribe them. The patterns use no lookarounds or backreferences, so they are valid in Go's RE2 syntax; confirm each compiles.
- **Collector logic** for AWS static versus session splitting, SSO cache expiry, and the OpenSSH key header parse that distinguishes encrypted from plaintext keys.
- **Keychain dump parser and classifier** as a starting point (see M5 for its caveats).
- **Report design.** Carry the CSS and section order over as they are. It renders cleanly at 1100px and 390px in light and dark.
- **Expected results** in section 11. The Go version must reproduce them.

### Do not take

| Prototype behavior                                                          | Go design instead                                                                                    |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Diff compares against the latest snapshot regardless of terminal            | Context-keyed history (section 5)                                                                    |
| One id, so rotation looks like resolve plus new                             | `SlotID` plus `ID`, with a "rotated" state                                                           |
| `SECRET_NAME` matches a bare `AUTH`, so `author` is a hit; no entropy check | See M3                                                                                               |
| Subprocesses resolved through `PATH`                                        | Invariant 8                                                                                          |
| Raw values passed around as plain strings                                   | `Secret` type                                                                                        |
| Agent approval guessed from the socket path                                 | Keep the heuristic but label it `confidence: medium` and say why in `Detail`                         |
| Encrypted SSH key always scored as gated                                    | Also check `~/.ssh/config` for `UseKeychain yes`; if set, mark the key silent with medium confidence |
| Unused `seen` variable, `FIX["gpg"]` with no collector                      | Drop                                                                                                 |

### What the prototype proved, and did not

Verified on Linux against a fixture home: detection of the section 11 fixtures, placeholder and `node_modules` exclusion, the leak check, diffing, duplicate cross-referencing, SSH detection on synthetic key blobs, and the Keychain parser on one hand-written sample.

Never verified: anything on macOS. No real Keychain dump, no protected-folder probe, no Full Disk Access detection has been observed.

## 8. Milestones

M0 and M1 are sequential and define the contracts. After M1, the M2 collectors are independent and can be built by parallel agents. M3 and M4 can run alongside M2. M5 needs Glenn.

### M0. Skeleton and guardrails

- Repository, `go.mod` pinned to the current stable Go release, layout from section 5.
- `Secret`, `Env`, `Collector`, the runner with containment, and an empty report.
- Every check in section 6 passing against a tool that has no collectors yet.
- A `make test` or `./test.sh` that runs everything.

### M1. Core

- Model, fingerprinting and salt creation, scoring, ranking, state directory, snapshot writing, context-keyed diff with new, resolved, and rotated.
- Terminal summary and `-json` output.
- Acceptance: table-driven tests for the scoring formula; diff tests covering same-context and cross-context runs and rotation.

### M2. Collector parity

One agent per group is reasonable. Each collector ships with fixture tests through `Env`.

- Known files, AWS, SSH.
- Ambient: environment, shell startup files, history, dotenv sweep with a time budget.
- AI tooling configs.
- Context and reach: parent chain via `/bin/ps`, Full Disk Access probe, reach table with sizes under a per-target time budget.
- Keychain: parser and classifier against `testdata` samples.
- HTML report via `html/template` with embedded CSS.

Acceptance: the section 11 table reproduced exactly, and the leak test extended to every fixture.

### M3. Matcher precision

- Secret-like names match on token boundaries (`AUTH_TOKEN`, `_auth`), not substrings (`author`).
- A Shannon entropy floor for values matched by name only. Known-prefix tokens are exempt.
- A test corpus of at least 20 true positives and 20 known false positives, with both rates printed by the test.

### M4. Usable authority through helpers

The prototype's largest gap. Many tools keep nothing readable on disk but hand the token to any caller: the git osxkeychain credential helper, `gh auth token`, `docker-credential-osxkeychain`, `gcloud auth print-access-token`, `aws configure export-credentials`. Only the SSH agent is covered today.

Rules:

- Output goes straight into a `Secret` and is fingerprinted. No shell, no temp file.
- Only invoke helpers that answer offline. The git and Docker credential helpers do. `gcloud auth print-access-token` may refresh over the network, so detect it from configuration and mark it medium confidence.
- Close stdin, set `GIT_TERMINAL_PROMPT=0`, enforce a short timeout so nothing blocks on a prompt.
- If a helper raises a macOS prompt, that is a result (gated), not a failure. This cannot be observed on Linux; structure the code so M5 can confirm it.
- Whether these probes run by default is an open question for Glenn (section 9). Build them behind a flag until he answers.

Acceptance: findings for git credential helpers (hosts from `~/.gitconfig` plus the well-known forges), `gh`, and Docker credential stores; tests use a stub `Env.Run`; leak test covers helper output.

### M5. macOS validation (needs Glenn)

Nothing here can be done without a real Mac. Your job is to make Glenn's part small and safe.

Deliver:

- **A build path.** Either instructions for Glenn to build from source on his Mac, or a binary you build with `GOOS=darwin` and flags for reproducibility (`-trimpath`, stripped build id) so he can confirm it matches his own build. Find out first whether he has Go installed (section 9).
- **A sanitizer subcommand** (`exposure-audit -sanitize-keychain-sample`) that captures the structure of `security dump-keychain -a` with every attribute value replaced by a same-length placeholder, so the result is safe to commit to `testdata`. Glenn must read the output before sharing it.
- **A checklist:** run from Terminal, from his IDE's terminal, and from any other terminal he installs packages in; note every macOS prompt; send back only the terminal summary.

Then, with his results, settle these unknowns and record the answers in code comments:

- Does the Keychain parser handle real output?
- Does the dump include partition-list entries, and can the classifier use them? The prototype ignores partition lists, so its "silent" verdicts are only likely.
- Does `dump-keychain -a` itself ever prompt on current macOS?
- Do protected-folder probes prompt, fail silently, or succeed, per terminal app?
- Does a cross-compiled binary run without a Gatekeeper block when delivered the way you delivered it?
- Items in the newer data-protection keychain are not in the login keychain dump. Decide with Glenn whether that matters, given that an unsigned process cannot read those items either.

### M6. Content sweep

Find secrets outside known locations, using the M3 matcher over a bounded file set (size cap, extension allowlist, time budget, concurrent walk).

Optionally wrap `trufflehog` or `gitleaks` if one is already installed. Never install either. TruffleHog verifies findings over the network by default and must be run with verification disabled. Their raw output is never written to disk.

### Later, not scheduled

Opt-in online verification of token validity and scope. Signing, notarization, and distribution.

## 9. Open questions for Glenn

1. Is Go installed on his Mac, and does he want to build from source or receive a binary?
2. Should the helper probes in M4 run by default? They cause real tokens to be emitted into the tool's memory, where they are fingerprinted and discarded.
3. Are the score weights right once he has seen his own results? In particular, should a passphrase-protected SSH key really be a 90% reduction?
4. Is an opt-in online verification mode wanted at all?
5. When does sharing with others become a goal? That triggers the signing and notarization work.

## 10. How to hand work back

For each milestone or collector, return:

- What changed, as a commit list.
- Test output, including the leak test and the dependency check.
- What you could not verify and why. Expect "needs macOS" often.
- Any invariant you had to bend, stated plainly, with the reason.
- New questions for Glenn, separated so they are easy to find.

## 11. Fixtures and expected results

The Go version must reproduce these. Tokens are described, not written out; assemble them at runtime.

| Path in fake home              | Content                                                                  | Expected result                                   |
| ------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------- |
| `.npmrc`                       | registry auth line with an `npm_` + 36 character token                   | propagation, 10.0                                 |
| `.aws/credentials`             | `[default]` static key pair; `[tmp]` pair with a session token           | cloud 8.0 static; cloud 3.2 session               |
| `.config/gh/hosts.yml`         | `oauth_token:` with a `ghp_` token                                       | propagation, 10.0                                 |
| `.zsh_history`                 | curl command containing the same `ghp_` token                            | propagation 10.0, cross-referenced as a duplicate |
| `.zshrc`                       | exported `sk-proj-` key; a second export whose value is `$(op read ...)` | service 5.0; placeholder ignored                  |
| `code/app/.env`                | a database password and an `sk_live_` key                                | service 6.2, two secrets                          |
| `code/app/.env.example`        | `API_KEY=your_key_here`                                                  | ignored                                           |
| `code/app/node_modules/x/.env` | any secret                                                               | ignored                                           |
| `.cursor/mcp.json`             | MCP server env block with a `github_pat_` token                          | propagation, 10.0                                 |
| `.ssh/id_plain`, `.ssh/id_enc` | OpenSSH key blobs with cipher `none` and `aes256-ctr`                    | propagation 10.0; propagation gated 1.0           |
| environment                    | a variable named `MY_SERVICE_TOKEN` with a random value                  | generic 3.0                                       |

Behavioral checks with the same fixture: deleting `.npmrc` and rerunning lowers the total by 10.0 and lists the finding as resolved; replacing its token lists it as rotated with the total unchanged.

## 12. Keychain dump format, as the prototype assumes it

Hand-written from memory of the format and unconfirmed against a real Mac. Use it to start the parser, and replace it with sanitized real samples in M5.

```
keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="gh:github.com"
    "acct"<blob>="me"
    "svce"<blob>="gh:github.com"
access: 2 entries
    entry 0:
        authorizations (1): encrypt
        don't-require-password
        description: gh:github.com
        applications: <null>
    entry 1:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        don't-require-password
        description: gh:github.com
        applications (1):
            0: /usr/bin/security (OK)
```

Classification of the entries that include `decrypt`: `applications: <null>` means any application (silent); a listed path that is not inside an `.app` bundle means a command-line tool can read it (silent, via that tool); only `.app` paths means app-gated; no decrypt entry means undetermined.

## 13. References

Not yet checked against this document's threat description. Read before relying on specifics.

- Semgrep, "Sha1-Hulud: The Second Coming of the NPM Worm is Digging For Secrets": https://semgrep.dev/blog/2025/digging-for-secrets-sha1-hulud-the-second-coming-of-the-npm-worm
- SentinelOne, "Defending Against Sha1-Hulud: The Second Coming": https://www.sentinelone.com/tw/blog/defending-against-sha1-hulud-the-second-coming/
- Expel, "Stories from the SOC: The second coming of Shai Hulud": https://expel.com/blog/the-second-coming-of-shai-hulud/
