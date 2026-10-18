# Exposure Audit (Go): agent handoff

You are building a Go implementation in this repository. The Python prototype is at `prototype/exposure_audit.py` (v0.1.0, 990 lines, sha256 prefix `b2a9b3a3434feec9`). Treat it as a behavioral reference and a source of data tables, not as code to extend. It has known design defects (section 7) that the Go version fixes by design instead of porting.

[`REVIEW.md`](REVIEW.md) records the adversarial review of this document (2026-10-12): every finding has an ID (`A-nn`, `R-nn`), a status, and a pointer back here. IDs are cited in this document where a rule came from a finding. Keep `REVIEW.md` current as you build (section 10).

## 1. What we are building and why

A local macOS utility that answers one question:

> Show me, in under a minute and fully offline, everything a malicious install script launched from my terminal could silently read or use, ranked by blast radius, so I know what to fix first.

The reference threat is the Shai-Hulud npm worm family (2025). Confirmed for the second wave (section 13): an injected `preinstall` hook ran `npm install → sh → node → bun → trufflehog` as the logged-in user, with no root and no exploit. It harvested npm, GitHub and cloud credentials from files and environment variables, then used the stolen GitHub token to register the machine as a self-hosted Actions runner and republish itself. None of the sources checked mention the Keychain or the SSH agent; the collectors for those cover plausible variants, not the reference case.

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
- Blocking or sandboxing installs. Reporting whether install scripts are allowed to run is in scope (decision 19); changing that setting is not.
- Fleet or team management.
- Windows or Linux as targets. Linux matters only because that is where agents build and test.

## 2. Decisions already made

Do not reopen these without asking the maintainer.

1. **Scope:** credentials are scored. Other data (Documents, iCloud, Mail, browser profiles) gets a coarse reach check with sizes and is not scored.
2. **Audience:** the maintainer only for now, built so it could be shared later.
3. **Depth:** offline inventory. Checking whether a token is live or what it is scoped to needs network calls and is a possible later opt-in mode.
4. **Tracking:** salted fingerprints and run history from the start.
5. **Language:** Go, standard library only, no cgo, one static binary. Chosen over Python (not on a stock Mac, interpreter is attack surface), Swift (agents cannot build or test Apple-framework code on Linux), Rust (needs crates for hashing, JSON, and regex), Bash (unsafe secret handling), and Ruby (deprecated on macOS).

One accepted cost of decision 5: no native Keychain API access. Keychain analysis parses the output of `/usr/bin/security`. The maintainer's macOS run (section 7) showed the dump is parseable and does not prompt.

Decided 2026-10-12, after the review and a prototype run on a developer Mac:

6. **Observe macOS before building.** Done ([A-01](REVIEW.md#a-01)). Remaining macOS unknowns are in M5.
7. **Score each credential once** ([A-14](REVIEW.md#a-14)). A credential is a unique fingerprint. Its score is the highest it earns in any location; every location is listed. The prototype's multiplier for several secrets in one file is dropped: each secret already scores as its own credential ([A-03](REVIEW.md#a-03)).
8. **"Fix first" is ordered by class tier, then score** ([R-01](REVIEW.md#r-01)). A worm-vector token can never rank below a `.env` of cloud keys. Section 5 defines the tiers.
9. **Committed dotenv files score × 0.5** ([R-02](REVIEW.md#r-02)).
10. **Approvals cached for a time window score × 0.5, as gate `windowed`** ([A-19](REVIEW.md#a-19)): the 1Password CLI app integration and the 1Password SSH agent. `sudo` is never run; a cached sudo ticket is listed as a known blind spot.
11. **New class `agent`, weight 5** ([R-05](REVIEW.md#r-05)), for coding-agent session tokens such as `CLAUDE_CODE_MESSAGING_TOKEN`, until their reach is known.
12. **Full Disk Access is pinned to the top of "Fix first", unscored** ([R-06](REVIEW.md#r-06)).
13. **An AWS SSO cache holding a `refreshToken` is static, not session** ([A-16](REVIEW.md#a-16)).
14. **Credential helpers are never executed** ([A-23](REVIEW.md#a-23)). Whether a helper hands out its token silently is inferred from configuration plus the Keychain access list (M4). None of the permitted programs prints a secret ([A-09](REVIEW.md#a-09)).
15. **The HTML report is written only with `-open`, and deleted afterwards** ([A-25](REVIEW.md#a-25)).
16. **History never stores Keychain service or account names** ([A-27](REVIEW.md#a-27)).
17. **The protected-folder probe is opt-in** (`-probe-folders`) ([A-28](REVIEW.md#a-28)).
18. **Exit codes:** 0 = complete run; 1 = report produced but at least one collector failed, timed out, or was partial; 2 = usage error or unusable state directory ([A-31](REVIEW.md#a-31)). `-h` and `-version` are requests, not errors: they exit 0.
19. **An unscored "Prevention" section** reports whether package managers run install scripts and whether release-age delays are set ([A-32](REVIEW.md#a-32)).
20. **The content sweep (M6) is post-MVP** ([A-24](REVIEW.md#a-24)).
21. **A passphrase-protected SSH key that no agent holds keeps the 0.1 gated multiplier.**
22. **Build from source on a developer Mac.** Go 1.26 is installed through mise.

## 3. Invariants

Every change must preserve these. Section 6 says how each is enforced mechanically.

1. **No secret values at rest or on screen.** Values are read into memory, fingerprinted, and dropped. This covers the report, history, stdout, stderr, error strings, panics, and test logs.
2. **No network.** The binary must not link the `net` or `net/http` packages, and must not run a subprocess that makes network calls. It must not read files that would be downloaded on access (section 5, Collectors).
3. **Read-only outside `~/.exposure-audit`.** That directory is 0700; files in it are 0600.
4. **Standard library only.** `go.mod` has no `require` lines and there is no `go.sum`. `CGO_ENABLED=0`.
5. **Unprivileged.** No sudo, no entitlements, no app bundle with its own permissions. Any of these would measure the wrong position.
6. **A broken collector must not sink the run.** Collector errors, panics and timeouts are contained and reported; the report still renders.
7. **Never read a Keychain item's value.** Access-list metadata only. `security dump-keychain` is called with `-a` and never `-d`.
8. **Only four subprocesses, by absolute path, never through a shell:** `/usr/bin/security`, `/usr/bin/ssh-add`, `/bin/ps`, `/usr/bin/open`. A tool that resolves programs through `PATH` can be hijacked by the very thing it audits. No other program is executed (decision 14).

## 4. Rules for agents

- **Never run the tool against a real home directory**, including a linked developer Mac, unless the maintainer explicitly asks in that session. Tests use `t.TempDir()` homes.
- **Never paste a report, snapshot, or real path listing into a conversation or commit.** The report is a map of where secrets live. The terminal summary (titles, paths, scores) is the only thing the maintainer has agreed to share back.
- **Build fake tokens at runtime.** Fixtures need strings that match real token formats. Committing them as literals trips secret scanners and push protection. Assemble them by concatenation in test helpers.
- **Report honestly.** If something is unverified on macOS, say so in a code comment and in your handback.
- **Ask before:** changing score weights, adding any network path, adding a dependency, enabling cgo, executing a new program, or changing an invariant.

## 5. Architecture

### Layout

```
go.mod                      module exposure-audit, no requires
main.go                     flags, orchestration, exit codes
model.go                    Finding, Hit, Credential, Item, Snapshot, enums
secret.go                   Secret type
score.go                    scoring, credential grouping, tiers, ranking
fingerprint.go              salt handling, HMAC, output leak check
env.go                      Env abstraction (below)
state.go                    state directory, history, diff
match.go                    token patterns and the generic matcher
gitindex.go                 "is this file tracked by git" from .git/index
collect_files.go            table-driven known credential files
collect_aws.go
collect_ssh.go              key files, agents, 1Password agent
collect_ambient.go          environment, shell files, history, dotenv sweep
collect_keychain.go         dump parser and classifier
collect_helpers.go          helper inference from config + Keychain (M4)
collect_ai.go
collect_reach.go            context, Full Disk Access inference, data reach
collect_prevention.go       install-script controls (unscored)
report.go                   terminal summary; html/template report, CSS embedded
sanitize.go                 -sanitize-keychain-sample
*_test.go
testdata/                   sanitized samples only; no real output
prototype/exposure_audit.py reference only
HANDOFF.md
REVIEW.md                   review findings, decisions, progress tracker
```

One `main` package is fine at this size. Split into internal packages only if it clearly helps.

### The Env abstraction

Collectors never call `os.Getenv`, `os.UserHomeDir`, `exec.Command`, or `time.Now` directly. They receive an `Env`:

```go
type Env struct {
    Home    string
    Root    string            // "/" except in tests: the few paths outside the home resolve under it (A-41)
    Environ map[string]Secret // values are secrets too; a map[string]string leaks under t.Logf("%+v", env) (A-10)
    // Plain(name) returns the value of a variable on PlainEnv as a string, and "" for any other name.
    GOOS    string
    Now     time.Time
    PID     int               // start of the ps chain for the context key
    Run     func(ctx context.Context, c Cmd) (stdout []byte, exit int, err error)
}

type Cmd struct {
    Path string   // one of the four in invariant 8
    Args []string
    Env  []string // full replacement environment; stdin is always closed (A-08)
}

type Collector interface {
    Name() string
    Collect(ctx context.Context, env *Env) ([]Finding, error)
}
```

`Run` returns plain bytes because none of the four permitted programs prints a secret value: the Keychain dump is metadata (invariant 7), `ssh-add -l` prints public fingerprints, `ps` prints process names. If a later change ever runs a program whose output is a secret, `Run` must return a `Secret` for it ([A-09](REVIEW.md#a-09)).

A few variables are needed as plain strings and are not secrets. `Env.Plain(name)` returns them, and only them:

```go
// The only environment variables readable as plain text. A test asserts this list is exactly these five.
var PlainEnv = []string{"__CFBundleIdentifier", "TERM_PROGRAM", "SSH_AUTH_SOCK", "TMUX", "USER"}
```

The context key needs the first two; the SSH collector needs `SSH_AUTH_SOCK` to pass to `ssh-add` and to recognise a 1Password socket ([A-33](REVIEW.md#a-33)).

This is what makes every collector testable on Linux: tests pass a temp home, a fake environment, and a stub `Run` that returns canned output (for example a sample Keychain dump). It also gives one place to enforce invariant 8.

### Collectors and the runner

Collectors run concurrently under one global deadline of 60 seconds, with per-collector budgets derived from it ([A-12](REVIEW.md#a-12)). Each is wrapped so that an error or panic becomes an entry in `Snapshot.Errors` holding only the collector name and a fixed category string. Never store `err.Error()`: some standard library errors quote their input (`strconv` does), which could be a secret.

- `recover` only catches panics in its own goroutine. Collectors must not start goroutines with a bare `go`; they use a runner-provided helper that recovers and reports ([A-11](REVIEW.md#a-11)).
- A collector that ignores `ctx` (a hung mount, a file-provider directory) cannot be stopped. At the deadline the runner stops waiting, records a timeout, and renders without it.
- Each collector reports a status: `complete`, `partial` (budget hit), `failed`, `timeout`, or `skipped` (not applicable, such as the Keychain on Linux, or turned off, such as `-skip-keychain`). The diff treats every status except `complete` as not complete, so skipping the Keychain does not look like a large improvement. The exit code treats `skipped` as normal ([A-13](REVIEW.md#a-13), [A-37](REVIEW.md#a-37)).
- Never read a file that iCloud or a file provider has evicted: check `SF_DATALESS` (`0x40000000` in `syscall.Stat_t.Flags`) first. Reading one downloads it, which is network traffic caused by the tool ([A-29](REVIEW.md#a-29)). Size measurement uses `stat` only.
- Walks are in sorted order, so a budget cut drops the same files each time.
- Walks never enter TCC-protected folders unless `-probe-folders` is set or Full Disk Access is inferred `yes`: `Desktop`, `Documents`, `Downloads`, `Library/Mobile Documents`, `Library/CloudStorage`, and `Pictures`. Listing one can raise the permission prompt that decision 17 makes opt-in. The prototype had this rule (`skip_protected`) ([A-35](REVIEW.md#a-35)).
- Full Disk Access inference (M2) runs synchronously before the concurrent collectors start, because the sweep depends on it. It is three directory reads and cannot prompt.

### The Secret type

Raw values must be hard to leak by accident:

```go
// The pointer is deliberate. fmt does not call String or Format on unexported
// struct fields; it prints them raw. A []byte field leaks the value under %s
// (verified with Go 1.26). A pointer field prints as an address. (A-02)
type Secret struct{ p *[]byte }
func (Secret) String() string                 { return "[redacted]" }
func (Secret) GoString() string               { return "[redacted]" }
func (Secret) Format(f fmt.State, c rune)     { io.WriteString(f, "[redacted]") }
func (Secret) MarshalJSON() ([]byte, error)   { return nil, errors.New("secret is not serializable") }
func (s Secret) Fingerprint(salt []byte) string
```

The matcher and collectors pass `Secret` values, never `string`. The only way out of a `Secret` is `Fingerprint`. No model type has a field that can hold one.

Leaks are more likely through fields built from parsed text than through values ([A-26](REVIEW.md#a-26)). Example: a `~/.gitconfig` `url "https://x-access-token:<token>@github.com/".insteadOf` line turned into a host name puts the token in `Location`. Build `Location` from known paths and fixed labels, never from parsed content. Before anything is written (stdout, `-json`, report, history), split the output on characters outside `[A-Za-z0-9_\-.+/=:]`, HMAC each candidate of 8 or more characters with the salt, and abort the write if one matches a collected fingerprint. This catches real-world leaks without keeping values in memory.

### Data model

```
Finding     one location where credentials were found (what collectors emit)
  ID, SlotID, Layer, Kind, Title, Location, Lifetime, Gate, Committed,
  Detail, Notes, Confidence, Fix, Hits []Hit, Collector

Hit         one secret at that location
  Fingerprint, Class, Name   // Name: variable or key name if known, never the value

Credential  one fingerprint across all findings (derived in score.go)
  Fingerprint, Class, Score, Findings []ID

Item        one entry in "Fix first" (derived in score.go)
  credentials that appear in exactly the same set of findings (by SlotID), grouped
  Title, Locations, Credentials, Tier, Score
  Title is the title of the highest-scoring finding among them (A-39)
```

- `Class`: `propagation` (npm, GitHub, registries, SSH: makes the victim a worm vector), `cloud`, `agent`, `service`, `generic`.
- `Gate`: `silent`, `windowed` (an approval is cached for a while, then needed again), or `gated` (needs a passphrase, touch, or approval each time).
- `Lifetime`: `static` or `session`.
- `Committed`: the file is tracked by git (dotenv files only).
- `Fingerprint`: `hex(HMAC-SHA256(salt, value))[:12]`. Salt is 32 random bytes in `~/.exposure-audit/salt`.
- SSH keys are fingerprinted by public key, not file text: the `SHA256:` value `ssh-add -l` prints, which is `base64(sha256(public key blob))` without padding. The public half of an `openssh-key-v1` file is cleartext even when the private half is encrypted. This makes a key file and the same key in an agent one credential, and adding a passphrase is not a rotation ([A-15](REVIEW.md#a-15)). If the public key cannot be extracted (an encrypted PEM key, an unknown format) and no `.pub` file sits next to it, fingerprint the file text instead at medium confidence ([A-38](REVIEW.md#a-38)).
- Keychain items cannot be fingerprinted by value (invariant 7). Their `SlotID` is `sha256(kind | HMAC(key))[:12]` and their hit fingerprint is `HMAC(key|mdat)`, where `key` is Apple's unique key for the item's class: `kc|genp|svce|acct` for generic passwords and `kc|inet|acct|sdmn|srvr|ptcl|atyp|port|path` for internet passwords, with `|` and `\` inside a field backslash-escaped. The label is not part of either, so renaming an item keeps its slot ([A-54](REVIEW.md#a-54), [A-59](REVIEW.md#a-59)). A changed `mdat` changes `ID` but not `SlotID`, so the ordinary rotation rule detects it. The persisted `Location` is built from that `SlotID` (section 5, State on disk), never the reverse ([A-34](REVIEW.md#a-34)).
- Presence-only findings (a credential store that is not parsed) fingerprint `kind|relative path`.
- `SlotID`: `sha256(kind | location)[:12]`, except Keychain items (above). Identifies where credentials live.
- `ID`: `sha256(kind | location | sorted fingerprints)[:12]`. Identifies the specific credentials in that place.

Two ids let the diff tell "modified" (same slot, different id) from "resolved" and "new". The prototype has only `ID` and cannot.

There is no compatibility requirement with the prototype's snapshot format. Version the snapshot schema from 1.

### Scoring

```
weight(hit in finding) = BASE[hit.Class] × L[finding.Lifetime] × G[finding.Gate] × C[finding.Committed]

BASE  propagation 10, cloud 8, agent 5, service 5, generic 3
L     static 1, session 0.4
G     silent 1, windowed 0.5, gated 0.1
C     committed dotenv 0.5, otherwise 1

credential score = highest weight over every hit with that fingerprint
credential class = highest class over those hits (propagation > cloud > agent > service > generic)
total            = sum of credential scores
```

Scores are `float64`. Round only for display and JSON, with `math.RoundToEven(x*10)/10`. `math.Round` rounds half away from zero, which differs from the prototype's Python `round` on values like 6.25 ([A-03](REVIEW.md#a-03)).

**Fix first.** Build items by grouping credentials that occur in exactly the same set of findings, compared by `SlotID`, so five secrets in one `.env` (and its four worktree copies) are one item. Grouping by `SlotID` rather than path keeps different kinds in one file apart: the AWS static and session credentials in `.aws/credentials` stay two items, with different fixes. Item score is the sum of its credential scores. Sort items by tier, then score descending, then location:

| Tier | Contents                                                                   |
| ---- | -------------------------------------------------------------------------- |
| 0    | Pinned: Full Disk Access on the launching terminal (unscored, decision 12) |
| 1    | Any propagation credential that is silent or windowed                      |
| 2    | Any cloud credential that is silent or windowed                            |
| 3    | Any agent or service credential that is silent or windowed                 |
| 4    | Generic, silent or windowed                                                |
| 5    | Everything gated                                                           |

An item's tier is the best tier among its credentials. The terminal shows the top 5 items, the report the top 12.

**Committed dotenv.** A dotenv file is committed if git tracks it. Determine this by reading the repository's `.git/index` directly; running `git` is not allowed (invariant 8). In a worktree, `.git` is a file containing `gitdir: <path>`; follow it. Support index versions 2 and 3 (paths stored whole) and 4 (paths prefix-compressed). If parsing fails, treat the file as not committed and set confidence to medium.

What the first real run showed (2026-10-12, a developer Mac, prototype, summary only):

- Dozens of findings without the Keychain, and more with it. That is a dump, not a short list.
- The top five were all `.env` files whose high scores came from several cloud-named variables in one file. Most were one file duplicated across git worktrees of one repository.
- No worm vector reached the top five, although several existed.

Decisions 7–9 are the response. The ranking fixture in section 11 encodes it.

### State on disk

```
~/.exposure-audit/
  salt                              32 bytes, 0600
  report.html                       only during -open, then deleted
  history/YYYYMMDDTHHMMSSZ.json     one snapshot per run, UTC
```

**History contents** (decision 16). Snapshots hold findings with titles and locations, so the diff is readable. Keychain findings are the exception: their persisted `Location` is `login keychain item <SlotID>`, using the Keychain `SlotID` defined in the data model. Service and account names appear only in live output (the terminal summary and the `-open` report), never in history or `-json`. The report's "How to read this" says that `~/.exposure-audit` is readable by the same attacker the tool models.

**Report** (decision 15). With `-open`: delete any stale `report.html`, write it 0600, run `/usr/bin/open` on it, wait 5 seconds so the browser can load it, then delete it. Every run deletes a leftover `report.html` at startup. Without `-open`, no HTML is written.

**Context key.** Each snapshot records the launching application and whether the shell runs under a coding agent. Diffs compare only against the most recent snapshot with the same key.

- **Application:** `__CFBundleIdentifier` from the environment, falling back to `TERM_PROGRAM`, then `unknown` ([A-05](REVIEW.md#a-05)). The `ps` parent chain is for display only. Observed on a developer Mac: inside tmux, `TERM_PROGRAM` is `tmux` and the chain ends at `tmux`, but `__CFBundleIdentifier` still held the terminal's bundle id.
- **Agent:** whether the parent chain (process names from `/bin/ps -o ppid=,comm= -p <pid>`, up to 8 levels) contains `claude`, `codex`, `cursor-agent`, `gemini`, `aider` or `goose`. Agent shells differ: the same terminal and tmux session gained `CLAUDE_CODE_MESSAGING_TOKEN` under Claude Code.
- **Not Full Disk Access** ([A-06](REVIEW.md#a-06)). Revoking it is a recommended fix; putting it in the key would reset history at that moment. A change in Full Disk Access is reported as a diff event.

Snapshot files are created with `O_EXCL`; on collision, append `-2`, `-3`, … ([A-30](REVIEW.md#a-30)).

**Diff** states per finding: `new`, `resolved`, `modified` (same `SlotID`, different `ID`: a secret replaced, added or removed in that place, or a changed Keychain `mdat`; it was `rotated` until 2026-10-17), and `unknown`. A finding whose collector was not `complete` in either run is `unknown`, never `resolved`, and the credentials only it holds are left out of both totals when computing the delta ([A-13](REVIEW.md#a-13)).

### Command line

```
exposure-audit [-open] [-json] [-probe-folders] [-skip-keychain] [-roots dir,dir] [-max-depth N]
exposure-audit -sanitize-keychain-sample
```

- Default output is the terminal summary: score and delta, finding and credential counts, launching app and agent, Full Disk Access, the top 5 "Fix first" items with a count of any left out, each change since the last run by name, collector notes, and one Prevention line that counts settings on and names the ones to fix.
- `-json` prints the snapshot (no Keychain names, decision 16).
- `-roots` defaults to the home directory; `-max-depth` to 5. Each `-roots` element is made absolute from the current directory, a leading `~` expands to the home (the shell does not expand it after a comma), and empty elements are ignored. A root that is not an existing directory is a usage error (exit 2, decision 18); a root inside a protected folder is not checked, since looking could raise the prompt. Accepted gap: parseFlags runs before Full Disk Access is inferred, so with Full Disk Access `yes` and no `-probe-folders`, a mistyped root inside a protected folder is walked, finds nothing, and the sweep reports complete. A root that is, or resolves through a symlink into, a protected folder is skipped unless `-probe-folders` is set or Full Disk Access is inferred `yes` (decision 17). Nested or repeated roots report each file once, and a nested root still reaches past `-max-depth` from its own top ([A-57](REVIEW.md#a-57), [A-60](REVIEW.md#a-60)).
- Exit codes per decision 18.

## 6. Enforcing the invariants

These tests are part of M0 and must exist before any collector is written.

| Invariant              | Mechanical check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No secret values       | Leak test: every fixture secret carries a unique marker; run the full tool; assert no marker in stdout, stderr, `-json` output, the `-open` report (written to the fixture home with a stub `open`), or any history file. Unit test: `fmt.Sprintf` with `%v`, `%+v`, `%#v`, `%s` and `json.Marshal` never yield the value for a bare `Secret`, a `Secret` in an unexported struct field, and a `Secret` in a slice and a map. The bare case alone passes even with the leaky `[]byte` layout. Output check: a `Location` built from a fixture value aborts the write |
| No network             | `go list -deps .` must not contain `net` or `net/http`, matched exactly. `html/template` legitimately pulls in `net/url` and `net/netip` (verified), so a prefix match on `net` would wrongly fail the build ([A-04](REVIEW.md#a-04))                                                                                                                                                                                                                                                                                                                                                  |
| Standard library only  | Test parses `go.mod` and fails on any `require`; fails if `go.sum` exists; build with `CGO_ENABLED=0`                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Read-only, permissions | Test snapshots the fixture home's file list and modes before and after a run, with and without `-open`; only `.exposure-audit` may differ, with 0700 and 0600, and no `report.html` remains                                                                                                                                                                                                                                                                                                                                                                          |
| Collector containment  | Test registers a collector that panics, one that errors, one that panics inside a goroutine started through the runner helper, and one that blocks past the deadline; the report renders on time; `Errors` holds four entries with no dynamic text; exit code is 1                                                                                                                                                                                                                                                                                                   |
| Partial runs           | Diff test: a finding from a collector marked `partial` in the second run is `unknown`, not `resolved`, and the delta excludes it                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Subprocesses           | Test wraps `Env.Run` and fails on any path outside the four in invariant 8                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

Also run `go vet` and `gofmt -l` in the test script. The whole suite should finish in under 30 seconds on Linux.

## 7. What to take from the prototype, and what not to

### Take

- **Data tables.** `SPECS` (about 30 credential files with capture patterns), `TOKEN_RX`, `REACH_TARGETS`, `AI_FILES`, `FIX` texts, `SKIP_DIRS`. Transcribe them. The patterns use no lookarounds or backreferences, so they are valid in Go's RE2 syntax; confirm each compiles. Add these while transcribing:
  - History ([A-07](REVIEW.md#a-07)): `~/.zsh_sessions/*.history` (Apple Terminal's per-session files; the directory was observed on a developer Mac), `~/.bash_sessions/*`, `~/.viminfo`.
  - `SPECS`, propagation class ([A-21](REVIEW.md#a-21)): `~/.yarnrc.yml` (`npmAuthToken`; also project-level copies in the sweep), `~/.bundle/config` (`BUNDLE_<HOST>: user:token`), `~/.config/git/credentials` (git's XDG credential store, same pattern as `.git-credentials`), `~/.config/glab-cli/config.yml` (`token:`).
  - Sweep filenames, service class: `config/master.key`, `config/credentials/*.key` (Rails). Whole-file value, presence-style fingerprint of the content.
  - Credentials embedded in URLs ([A-20](REVIEW.md#a-20)): one pattern, `[a-z][a-z0-9+.-]*://[^:/\s@]+:(<secret>[^@\s]+)@`, applied to environment values (including `*_URL`, which `ENV_SKIP` currently drops), shell files, dotenv files, and `.git/config` of every repository the sweep passes (the sweep skips `.git` otherwise). Class by host: GitHub, GitLab, npm or PyPI hosts are propagation; otherwise by variable name; otherwise generic.
  - SSH agents named by `IdentityAgent` in `~/.ssh/config`, not only `$SSH_AUTH_SOCK` ([A-22](REVIEW.md#a-22)).
  - A known file's class is a floor: a recognised token format inside it raises the class, so a `ghp_` token in `.netrc` is propagation ([A-55](REVIEW.md#a-55)).
  - Drop the AWS access key ID pattern (`A[KS]IA…`) from `TOKEN_RX`: the ID is an identifier, and the secret key is the credential ([A-52](REVIEW.md#a-52)).
  - Environment findings use a fixed location per class, `environment (<class>)`, so the diff detects rotation ([A-46](REVIEW.md#a-46)).
  - Class-name rules need token boundaries ([A-17](REVIEW.md#a-17)): `PROP_NAME_RX` matches `GH_` inside `HIGH_WATER_TOKEN`. Match names split on `_`, `-` and `.`.
  - Agent tokens (decision 11): a secret-like name whose first segment is `CLAUDE_CODE`, `CLAUDECODE`, `CODEX`, `CURSOR`, `GEMINI_CLI`, `AIDER`, `GOOSE` or `WINDSURF` is class `agent`. Fix text: "Coding-agent sessions pass this token to every command they run, including package installs. Find out what it authorizes, and run installs from a plain terminal or a sandbox."
  - `REACH_TARGETS` labels browser and app folders under `Application Support` as "open". macOS 27 reportedly blocks some of them without a prompt (section 13, [R-04](REVIEW.md#r-04)). Keep measuring; drop the label column.
- **Collector logic** for AWS static versus session splitting and the OpenSSH key header parse that distinguishes encrypted from plaintext keys. Change SSO caches (decision 13): a cache file with a `refreshToken` is a static cloud credential at medium confidence, reported whether or not its access token has expired, because the refresh token mints new ones. Fingerprint the refresh token. Caches without one keep the prototype's expiry logic.
- **Keychain dump parser and classifier** as a starting point (see M2 and M5).
- **Report design.** Carry the CSS and section order over, and add Prevention after Data reach. It renders cleanly at 1100px and 390px in light and dark.

### Do not take

| Prototype behavior                                                          | Go design instead                                                                                                                     |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Diff compares against the latest snapshot regardless of terminal            | Context-keyed history (section 5)                                                                                                     |
| One id, so rotation looks like resolve plus new                             | `SlotID` plus `ID`, with a "modified" state                                                                                           |
| One score per location, multiplier for several secrets, duplicates add up   | One score per credential (decision 7)                                                                                                 |
| Ranking by score alone                                                      | Tiers (decision 8)                                                                                                                    |
| `SECRET_NAME` matches a bare `AUTH`, so `author` is a hit; no entropy check | See M3                                                                                                                                |
| Subprocesses resolved through `PATH`                                        | Invariant 8                                                                                                                           |
| Raw values passed around as plain strings                                   | `Secret` type                                                                                                                         |
| Full Disk Access from reading `TCC.db`                                      | Inferred from reach results (M2); the file is gone on macOS 27                                                                        |
| Folder probe on by default                                                  | `-probe-folders` (decision 17)                                                                                                        |
| Report always written and kept                                              | Only with `-open`, then deleted (decision 15)                                                                                         |
| Agent approval guessed from the socket path                                 | 1Password socket → `windowed`; other names keep the heuristic at `confidence: medium` with the reason in `Detail`                     |
| Encrypted SSH key always scored as gated                                    | Same key in an agent takes the agent's gate ([A-15](REVIEW.md#a-15)). Otherwise, if `~/.ssh/config` sets `UseKeychain yes`, silent at medium confidence |
| Unused `seen` variable, `FIX["gpg"]` with no collector                      | Drop                                                                                                                                  |

### What the prototype proved, and did not

Verified on Linux against a fixture home: detection of the original section 11 fixtures, placeholder and `node_modules` exclusion, the leak check, diffing, duplicate cross-referencing, SSH detection on synthetic key blobs, and the Keychain parser on one hand-written sample.

Observed on macOS (a developer Mac, macOS 27, 2026-10-12; the maintainer ran the prototype, agents saw only the terminal summary):

- `security dump-keychain -a` raised no prompt. Most entries include partition lists and `mdat` ([R-07](REVIEW.md#r-07), [R-08](REVIEW.md#r-08)).
- The Keychain added dozens of findings, some of them worm vectors. Partition lists were not modelled, so that is an upper bound.
- `~/Library/Application Support/com.apple.TCC/` does not exist (`ENOENT`) from any terminal, so the prototype's Full Disk Access check printed `n/a`. Reports say the user TCC database moved to a protected location (section 13).
- The `ps` chain ends at `tmux` (section 5, Context key).
- No folder probe prompted, but the terminal used may have had Full Disk Access, so this says nothing about a terminal without it.
- No collector reported an error or timeout. Run time was not measured.

## 8. Milestones

M0 and M1 are sequential and define the contracts. After M1, the M2 collector groups are independent. M3 and M4 can run alongside M2. Steps marked **maintainer** need a developer Mac.

### M0. Skeleton and guardrails

- `go.mod` pinned to Go 1.26, layout from section 5.
- `Secret`, `Env`, `Cmd`, `Collector`, the runner with containment, deadline and statuses, the output leak check, and an empty report.
- Every check in section 6 passing against a tool that has no collectors yet.
- `./test.sh` runs everything.

### M1. Core

- Model (`Finding`, `Hit`, `Credential`, `Item`), fingerprinting and salt creation, scoring, credential grouping, items and tiers, state directory, snapshot writing, context key, diff with new, resolved, modified and unknown, exit codes.
- Terminal summary and `-json` output.
- Acceptance: table-driven tests for every multiplier and tier; grouping tests (same fingerprint in two files is one credential; same set of locations is one item); diff tests covering same-context and cross-context runs, rotation, and partial collectors; exit-code tests.

### M2. Collector parity

Each collector ships with fixture tests through `Env`.

- Known files (with the section 7 additions), AWS (with decision 13), SSH (public-key fingerprints, `IdentityAgent`, 1Password agent → `windowed`).
- Ambient: environment (agent class, URL credentials), shell startup files, history, dotenv sweep with sorted walk and time budget, committed detection via `gitindex.go`, `.git/config` remotes.
- AI tooling configs.
- 1Password CLI (decision 10): if `/Applications/1Password.app` exists and an `op` binary exists at `/opt/homebrew/bin/op` or `/usr/local/bin/op` (stat only, never executed), emit one finding: kind `op-cli`, class propagation (a vault usually holds publishing tokens), gate `windowed`, confidence low, fingerprint `op-cli`. Detail: "If the 1Password app's CLI integration is on, a script in a terminal that unlocked `op` in the last ~10 minutes can read the vault without a prompt." Unverified on macOS.
- Context and reach: context key (section 5), `ps` chain for display, reach table with sizes under a per-target budget. Targets that need Full Disk Access (Mail, Messages, Safari) fail silently and never prompt, so they are always checked. TCC-protected folders (Desktop, Documents, Downloads, iCloud Drive, cloud storage, Photos, Contacts, Calendars, Notes) are checked only with `-probe-folders` or when Full Disk Access is `yes` ([A-36](REVIEW.md#a-36)). Full Disk Access is inferred ([R-03](REVIEW.md#r-03)): `yes` if any of Mail, Messages or Safari data is readable, `no` if all that exist are denied, `unknown` otherwise. When `yes`, emit the pinned tier-0 item: "Full Disk Access granted to <app>", fix "Remove it in System Settings → Privacy & Security → Full Disk Access unless something you run from this terminal needs it."
- Prevention (decision 19), unscored, config files only: npm `ignore-scripts` in `~/.npmrc`; Yarn Berry `enableScripts` and `npmMinimalAgeGate` in `~/.yarnrc.yml`; pnpm `minimum-release-age` and `only-built-dependencies` in pnpm's global rc (`~/Library/Preferences/pnpm/rc`); Bun `~/.bunfig.toml` `[install]` settings. Report each as on, off, or not configured, with a fix line. Key names and paths are from memory at medium confidence; confirm each against the tool's documentation and cite it in a comment.
- Keychain: parser and classifier. First build `-sanitize-keychain-sample`: it runs `security dump-keychain -a`, keeps structure and the fixed vocabulary (`class`, attribute tags, `authorizations`, `applications`, partition markers, `mdat` format), and replaces every attribute value, description, application path outside `/usr/bin`, `/bin`, `/usr/libexec`, `/System` and `/Library/Developer`, and partition value other than the `apple:`, `apple-tool:` and `teamid:` prefixes with a same-length placeholder. **The maintainer** runs it, reads the output, and commits it to `testdata/`. Then write the classifier against that sample, including partition lists: a command-line tool counts as a silent reader only if its partition (`apple-tool:` for Apple-signed tools such as `/usr/bin/security`) is in the item's partition list. Record the observed partition format in a code comment ([R-07](REVIEW.md#r-07)).
- Report via `html/template` with embedded CSS, written only for `-open` (section 5).

Acceptance: the section 11 tables reproduced exactly, and the leak test extended to every fixture.

### M3. Matcher precision

- Secret-like names match on token boundaries (`AUTH_TOKEN`, `_auth`), not substrings (`author`).
- A Shannon entropy floor for values matched by name only. Known-prefix tokens are exempt. Fixture values matched by name (the `.env` `DB_PASSWORD`, `MY_SERVICE_TOKEN`) are generated high-entropy so they pass ([A-18](REVIEW.md#a-18)).
- A test corpus of at least 20 true positives and 20 known false positives, with both rates printed by the test.

### M4. Helper inference

Many tools keep nothing readable on disk but hand the token to any caller who asks a helper. Decision 14: infer this, never run the helper. M4 enriches Keychain findings; it does not add separate ones, so nothing is counted twice.

- **git:** read `credential.helper` from `~/.gitconfig` and `~/.config/git/config`. If it is `osxkeychain`, Keychain `inet` items whose decrypt entry trusts a path ending in `git-credential-osxkeychain` become "Git credentials for <server>, usable by any process through git-credential-osxkeychain". Class propagation for GitHub, GitLab and Bitbucket servers, otherwise service.
- **gh:** if `~/.config/gh/hosts.yml` exists without an `oauth_token`, the token is in the Keychain. A `gh:<host>` item that trusts `/usr/bin/security` is "GitHub CLI token, readable by any process through /usr/bin/security", propagation.
- **Docker:** `credsStore` or `credHelpers` of `osxkeychain` or `desktop` in `~/.docker/config.json`; matching "Docker Credentials" items that trust a `docker-credential-*` tool are silent, service class.
- **gcloud and AWS SSO:** configuration only (an active gcloud account in `~/.config/gcloud`, `sso_session` in `~/.aws/config`), medium confidence. Their caches are already covered by the known-file and AWS collectors.
- Rotation for these comes from `mdat`.

Acceptance: fixture Keychain dumps plus configs produce the enriched findings above. Enrichment adds no findings and counts nothing twice; it may change an item's class, and so the total, where the class rules above differ from the plain Keychain heuristic, such as Bitbucket servers ([A-44](REVIEW.md#a-44)). The subprocess test confirms no helper is executed.

### M5. macOS validation (maintainer)

Deliver build-from-source instructions (`CGO_ENABLED=0 go build -trimpath -o exposure-audit .`) and a checklist: run from every terminal he installs packages in, with and without a coding agent; note every macOS prompt; send back only the terminal summary.

Settled already (section 7): the dump does not prompt; partition lists and `mdat` are present; TCC.db is gone; the `ps` chain stops at tmux.

Still open; record the answers in code comments:

- Does the Go parser handle the sanitized real dump?
- With partitions modelled, how many of the prototype's silent items stay silent?
- Does the Full Disk Access inference agree with System Settings, per terminal?
- Do protected-folder probes prompt, fail silently, or succeed in a terminal without Full Disk Access?
- Which terminal's permissions does a shell in tmux get: the one that started the tmux server, or the one attached?
- Does the 1Password detection match reality (is the CLI integration actually on)?
- Items in the data-protection keychain are not in the login keychain dump. Decide with the maintainer whether that matters, given that an unsigned process cannot read those items either.

### Later, not scheduled

- **M6, content sweep:** find secrets outside known locations with the M3 matcher over a bounded file set (size cap, extension allowlist, time budget). Optionally use an already-installed `gitleaks` or `trufflehog` with verification disabled; never install either. This needs a new entry in invariant 8.
- Opt-in online verification of token validity and scope.
- Signing, notarization, and distribution.

## 9. Open questions for the maintainer

None block the MVP.

1. Is an opt-in online verification mode wanted at all?
2. When does sharing with others become a goal? That triggers the signing and notarization work.
3. What does `CLAUDE_CODE_MESSAGING_TOKEN` authorize? The answer sets the `agent` class weight (decision 11).

## 10. How to hand work back

For each milestone or collector, return:

- What changed, as a commit list. Reference `REVIEW.md` IDs in commit messages (`A-08: ...`).
- Test output, including the leak test and the dependency check.
- What you could not verify and why. Expect "needs macOS" often.
- Any invariant you had to bend, stated plainly, with the reason.
- New questions for the maintainer, separated so they are easy to find.
- Updated rows in `REVIEW.md`, in the same commit as the change.

## 11. Fixtures and expected results

Tokens are described, not written out; assemble them at runtime. Values matched only by name are random and high-entropy.

### Base fixture

| Path in fake home              | Content                                                                  | Expected result                                                    |
| ------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `.npmrc`                       | registry auth line with an `npm_` + 36 character token                   | propagation 10.0                                                   |
| `.aws/credentials`             | `[default]` static key pair; `[tmp]` pair with a session token           | cloud 8.0 static; cloud 3.2 session                                |
| `.config/gh/hosts.yml`         | `oauth_token:` with a `ghp_` token                                       | propagation 10.0                                                   |
| `.zsh_history`                 | curl command containing the same `ghp_` token                            | same credential as `hosts.yml`: one item, two locations, 10.0 once |
| `.zshrc`                       | exported `sk-proj-` key; a second export whose value is `$(op read ...)` | service 5.0; placeholder ignored                                   |
| `code/app/.env`                | `DB_PASSWORD=<random>` and `STRIPE_KEY=<sk_live_ token>`                 | generic 3.0 + service 5.0, one item scoring 8.0                    |
| `code/app/.env.example`        | `API_KEY=your_key_here`                                                  | ignored                                                            |
| `code/app/node_modules/x/.env` | any secret                                                               | ignored                                                            |
| `.cursor/mcp.json`             | MCP server env block with a `github_pat_` token                          | propagation 10.0                                                   |
| `.ssh/id_plain`, `.ssh/id_enc` | OpenSSH key blobs with cipher `none` and `aes256-ctr`; no agent          | propagation 10.0; propagation gated 1.0                            |
| environment                    | `MY_SERVICE_TOKEN=<random>`                                              | generic 3.0                                                        |

Total: **68.2** (11 credentials). The prototype scored the same home 76.4, because it counted the `ghp_` token twice and the `.env` as one 6.2 finding.

"Fix first" order: the four propagation items (`.npmrc`, the `ghp_` token in two places, `mcp.json`, `id_plain`; tier 1), then AWS static and AWS session as two items (tier 2), then the `.env` item and the `sk-proj-` key (tier 3), then `MY_SERVICE_TOKEN` (tier 4), then `id_enc` (tier 5). Within a tier: score, then location.

Behavioral checks: deleting `.npmrc` and rerunning lowers the total by 10.0 and lists the finding as resolved. Replacing its token lists it as modified with the total unchanged. Exit code 0.

### Additional fixtures

Each is a separate fake home, so totals do not mix.

| Case                    | Setup                                                                                                                                                             | Expected                                                                |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Ranking ([R-01](REVIEW.md#r-01))          | `.npmrc` token; `code/app/.env` with four `AWS_*`-named secrets                                                                                                   | npm item first (tier 1, 10.0) above the `.env` item (tier 2, 32.0)      |
| Committed and worktrees | `code/app/.env.development` with an `sk_live_` value, tracked in a fake `.git/index`; `code/app-wt/` is a worktree (`.git` file) with the same file, also tracked | one credential, service 2.5, one item listing both locations            |
| SSH key in agent        | `id_enc` plus `SSH_AUTH_SOCK` set and a stub `ssh-add -l` printing `id_enc`'s `SHA256:` fingerprint                                                               | one credential, propagation silent 10.0, listing the file and the agent |
| 1Password agent         | `SSH_AUTH_SOCK` path containing `1password`; stub `ssh-add -l` lists one key                                                                                      | propagation windowed 5.0                                                |
| SSO refresh token       | `.aws/sso/cache/x.json` with `refreshToken` and an expired `expiresAt`                                                                                            | cloud static 8.0, medium confidence                                     |
| Agent token             | `CLAUDE_CODE_MESSAGING_TOKEN=<random>` in the environment                                                                                                         | agent 5.0                                                               |
| URL credentials         | `DATABASE_URL=postgres://app:<random>@db/app`; `code/app/.git/config` remote `https://x:<ghp_ token>@github.com/o/r.git`                                          | generic 3.0; propagation 10.0                                           |
| Full Disk Access        | readable `Library/Mail`                                                                                                                                           | pinned tier-0 item; total unchanged                                     |
| Partial run             | second run with the dotenv budget forced to zero                                                                                                                  | `.env` findings `unknown`, delta excludes them, exit code 1             |
| Prevention              | `.npmrc` with `ignore-scripts=true`                                                                                                                               | Prevention shows npm "on"; total unchanged                              |
| Protected folders | `Documents/app/.env` with an `sk_live_` value | default run: not read and not listed; with `-probe-folders`: service 5.0 |
| Skipped collector | second run with `-skip-keychain` after a run that had Keychain findings (stub dump) | Keychain findings `unknown`, delta excludes them, exit code 0 |
| Leak through location   | a parser that builds `Location` from a fixture value (test-only collector)                                                                                        | write aborted, nothing written, error category recorded                 |

## 12. Keychain dump format, as the prototype assumes it

Hand-written from memory of the format. A real dump confirmed partition lists and `mdat` are present but has not been inspected structurally; replace this with the sanitized sample from M2.

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

Classification of the entries that include `decrypt`: `applications: <null>` means any application (silent); a listed path that is not inside an `.app` bundle means a command-line tool can read it (silent, via that tool, subject to the partition rule in M2); only `.app` paths means app-gated; no decrypt entry means undetermined.

## 13. References

Shai-Hulud:

- Sysdig, "Return of the Shai-Hulud worm": https://www.sysdig.com/blog/return-of-the-shai-hulud-worm-affects-over-25-000-github-repositories
- Semgrep, "Sha1-Hulud: The Second Coming of the NPM Worm is Digging For Secrets": https://semgrep.dev/blog/2025/digging-for-secrets-sha1-hulud-the-second-coming-of-the-npm-worm
- SentinelOne, "Defending Against Sha1-Hulud: The Second Coming": https://www.sentinelone.com/tw/blog/defending-against-sha1-hulud-the-second-coming/
- Expel, "Stories from the SOC: The second coming of Shai Hulud": https://expel.com/blog/the-second-coming-of-shai-hulud/

macOS 27 changes. Unofficial reports, not confirmed by Apple documentation:

- Michael Tsai, "Golden Gate Application Support Protection": https://mjtsai.com/blog/2026/07/24/golden-gate-application-support-protection/ (user TCC database moved to a protected location; `com.apple.maclprotection` extended to some non-sandboxed apps' Application Support folders)
- Apple Developer Forums, "Detecting Full Disk Access on macOS 27": https://developer.apple.com/forums/thread/841091
- Apple Developer Forums, Chrome and Firefox folders blocked without a prompt: https://developer.apple.com/forums/thread/847030

Go:

- `fmt` and unexported fields: https://pkg.go.dev/fmt#hdr-Printing
