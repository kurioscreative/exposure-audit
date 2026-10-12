# Exposure Audit: adversarial review and progress tracker

Companion to [`HANDOFF.md`](HANDOFF.md). Reviewed 2026-10-12 against the original HANDOFF.md (commit `735722a`) and `prototype/exposure_audit.py` (v0.1.0, sha256 prefix `b2a9b3a3434feec9`).

The handoff is the spec. This file records why the spec changed, what is still undecided, and how far the build has got. No real paths, report contents, or secret values belong here ([HANDOFF section 4](HANDOFF.md#4-rules-for-agents)).

## How to use this file

- Every finding has an ID. Reference it in commit messages (`A-08: Cmd struct for Env.Run`) and in handbacks.
- When a commit changes a status, update the row in the same commit.
- Add new findings at the end of their table; never reuse an ID.
- Record decisions in the decision log with a date, then move the affected rows on.

| Status     | Meaning                                              |
| ---------- | ---------------------------------------------------- |
| `open`     | Raised, not yet in HANDOFF.md, no decision           |
| `decide`   | Needs Glenn; the HANDOFF section 9 question is given |
| `spec`     | Written into HANDOFF.md, not built                   |
| `built`    | Implemented, with a test that passes on Linux        |
| `verified` | Built, and confirmed on Glenn's Mac                  |
| `dropped`  | Rejected; the reason is in the decision log          |

Evidence tags: **[verified]** = run and observed, **[spec]** = reasoned from the documents, **[macOS]** = plausible but unobserved, with confidence.

## Progress

### Milestones

| Milestone                   | State       | Blocked by                                                      |
| --------------------------- | ----------- | --------------------------------------------------------------- |
| M5-lite: prototype on macOS | done        | —                                                               |
| Spec review                 | done        | —                                                               |
| M0 skeleton and guardrails  | done        | —                                                               |
| M1 core                     | done        | —                                                               |
| M2 collector parity         | in progress | M1; the Keychain classifier also needs Glenn's sanitized sample |
| M3 matcher precision        | not started | M1                                                              |
| M4 helper inference         | not started | M2 Keychain parser                                              |
| M5 macOS validation (Go)    | not started | M2                                                              |
| M6 content sweep            | post-MVP    | [Decision 20](HANDOFF.md#2-decisions-already-made)                                                     |

### Glenn's to-do list

- [ ] Check System Settings → Privacy & Security → Full Disk Access for Ghostty and every other terminal. The prototype cannot detect this on macOS 27. ([R-03](#r-03), [R-06](#r-06))
- [ ] Find out what `CLAUDE_CODE_MESSAGING_TOKEN` authorizes ([HANDOFF §9 Q3](HANDOFF.md#9-open-questions-for-glenn)). ([R-05](#r-05))
- [ ] During M2: run `exposure-audit -sanitize-keychain-sample`, read the output, commit it to `testdata/`. ([R-07](#r-07))
- [ ] During M5: run the checklist from each terminal, with and without a coding agent. (A-28 and the M5 list)
- [ ] Delete `~/.exposure-audit` left by the prototype once its report is no longer needed. ([A-27](#a-27))

## Decision log

| Date       | Decision                                                                                        | HANDOFF decision | Affects    |
| ---------- | ----------------------------------------------------------------------------------------------- | ---------------- | ---------- |
| 2026-10-12 | Observe macOS with the prototype before building (done the same day)                            | [6](HANDOFF.md#2-decisions-already-made) | [A-01](#a-01)       |
| 2026-10-12 | Build from source; Go 1.26 is installed through mise                                            | [22](HANDOFF.md#2-decisions-already-made) | —          |
| 2026-10-12 | Committed dotenv files score × 0.5                                                              | [9](HANDOFF.md#2-decisions-already-made) | [R-02](#r-02)       |
| 2026-10-12 | Never execute credential helpers; infer from config plus the Keychain access list               | [14](HANDOFF.md#2-decisions-already-made) | [A-23](#a-23), [A-09](#a-09) |
| 2026-10-12 | Score each credential once, highest across locations                                            | [7](HANDOFF.md#2-decisions-already-made) | [A-14](#a-14)       |
| 2026-10-12 | Drop the multiplier for several secrets in one file                                             | [7](HANDOFF.md#2-decisions-already-made) | [A-03](#a-03)       |
| 2026-10-12 | Order "Fix first" by class tier, then score                                                     | [8](HANDOFF.md#2-decisions-already-made) | [R-01](#r-01)       |
| 2026-10-12 | Cached approval windows (1Password CLI and SSH agent) score × 0.5 as `windowed`; never run sudo | [10](HANDOFF.md#2-decisions-already-made) | [A-19](#a-19)       |
| 2026-10-12 | New `agent` class, weight 5                                                                     | [11](HANDOFF.md#2-decisions-already-made) | [R-05](#r-05)       |
| 2026-10-12 | Full Disk Access pinned at the top of "Fix first", unscored                                     | [12](HANDOFF.md#2-decisions-already-made) | [R-06](#r-06)       |
| 2026-10-12 | AWS SSO cache with a `refreshToken` is static                                                   | [13](HANDOFF.md#2-decisions-already-made) | [A-16](#a-16)       |
| 2026-10-12 | Content sweep (M6) is post-MVP                                                                  | [20](HANDOFF.md#2-decisions-already-made) | [A-24](#a-24)       |
| 2026-10-12 | HTML report only with `-open`, deleted afterwards                                               | [15](HANDOFF.md#2-decisions-already-made) | [A-25](#a-25)       |
| 2026-10-12 | History stores no Keychain service or account names                                             | [16](HANDOFF.md#2-decisions-already-made) | [A-27](#a-27)       |
| 2026-10-12 | Folder probe is opt-in                                                                          | [17](HANDOFF.md#2-decisions-already-made) | [A-28](#a-28)       |
| 2026-10-12 | Exit codes 0 / 1 / 2                                                                            | [18](HANDOFF.md#2-decisions-already-made) | [A-31](#a-31)       |
| 2026-10-12 | Unscored Prevention section for install-script controls                                         | [19](HANDOFF.md#2-decisions-already-made) | [A-32](#a-32)       |
| 2026-10-12 | Passphrase-protected SSH key outside any agent keeps the 0.1 multiplier                         | [21](HANDOFF.md#2-decisions-already-made) | —          |
| 2026-10-12 | Build commits go directly on main                                                               | —                | —          |
| 2026-10-12 | Linux evidence for `built` comes from `./test.sh` in the `golang:1.26` Docker image              | —                | —          |
| 2026-10-12 | An output withheld by the leak check exits 1                                                    | [18](HANDOFF.md#2-decisions-already-made) | [A-26](#a-26), [A-31](#a-31) |
| 2026-10-12 | Build the Keychain parser and M4 against the §12 sample, then refit to Glenn's sanitized dump   | —                | [R-07](#r-07)       |

## Findings from the document review

| ID   | Finding                                                                                                                          | Evidence          | HANDOFF          | Status |
| ---- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ---------------- | ------ |
| <a id="a-01"></a>A-01 | macOS behavior was the main risk but was scheduled last. Run the prototype first                                                 | [spec]            | [§2 d6](HANDOFF.md#2-decisions-already-made), [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to)        | done   |
| <a id="a-02"></a>A-02 | `Secret{b []byte}` leaks under `%s`/`%v` when it is an unexported struct field; the planned unit test would pass anyway          | [verified]        | [§5](HANDOFF.md#5-architecture), [§6](HANDOFF.md#6-enforcing-the-invariants)           | built   |
| <a id="a-03"></a>A-03 | Fixture expected 6.2 for 6.25; Go's `math.Round` gives 6.3. Multiplier dropped; display rounds half to even                      | [verified]        | [§5 Scoring](HANDOFF.md#scoring)       | built   |
| <a id="a-04"></a>A-04 | `html/template` pulls in `net/url` and `net/netip`; the `net` dependency check must match exactly                                | [verified]        | [§6](HANDOFF.md#6-enforcing-the-invariants)               | built   |
| <a id="a-05"></a>A-05 | The `ps` chain ends at `tmux`; use `__CFBundleIdentifier` for the context key                                                    | [verified]        | [§5 State](HANDOFF.md#state-on-disk)         | built   |
| <a id="a-06"></a>A-06 | Full Disk Access in the context key resets history when it is revoked                                                            | [spec]            | [§5 State](HANDOFF.md#state-on-disk)         | built   |
| <a id="a-07"></a>A-07 | Missing history files: `.zsh_sessions/`, `.bash_sessions/`, `.viminfo`                                                           | [verified exists] | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to)               | spec   |
| <a id="a-08"></a>A-08 | `Env.Run` could not set environment or close stdin                                                                               | [spec]            | [§5 Env](HANDOFF.md#the-env-abstraction)           | built   |
| <a id="a-09"></a>A-09 | `Run` returned `[]byte` for helper tokens. Moot: no permitted program prints a secret (decision 14); rule kept for later changes | [spec]            | [§5 Env](HANDOFF.md#the-env-abstraction)           | built   |
| <a id="a-10"></a>A-10 | `Env.Environ map[string]string` put every environment value in a raw string                                                      | [spec]            | [§5 Env](HANDOFF.md#the-env-abstraction)           | built   |
| <a id="a-11"></a>A-11 | `recover` does not catch panics in goroutines a collector starts                                                                 | [spec]            | [§5](HANDOFF.md#5-architecture), [§6](HANDOFF.md#6-enforcing-the-invariants)           | built   |
| <a id="a-12"></a>A-12 | A collector that ignores `ctx` cannot be stopped; "under a minute" was never enforced                                            | [spec]            | [§5](HANDOFF.md#5-architecture), [§6](HANDOFF.md#6-enforcing-the-invariants)           | built   |
| <a id="a-13"></a>A-13 | A partial or failed collector made its findings look "resolved"                                                                  | [spec]            | [§5](HANDOFF.md#5-architecture), [§6](HANDOFF.md#6-enforcing-the-invariants), [§11](HANDOFF.md#11-fixtures-and-expected-results)      | built   |
| <a id="a-14"></a>A-14 | The same credential in several files was scored once per file                                                                    | [spec] + real run | [§2 d7](HANDOFF.md#2-decisions-already-made), [§5](HANDOFF.md#5-architecture)        | built   |
| <a id="a-15"></a>A-15 | Fingerprint SSH keys by public key so a key file matches the same key in the agent                                               | [spec]            | [§5](HANDOFF.md#5-architecture), [§11](HANDOFF.md#11-fixtures-and-expected-results)          | spec   |
| <a id="a-16"></a>A-16 | AWS SSO caches with a `refreshToken` last weeks but were scored as session                                                       | [macOS] medium    | [§2 d13](HANDOFF.md#2-decisions-already-made), [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to)       | spec   |
| <a id="a-17"></a>A-17 | Class-name rules matched inside words (`GH_` in `HIGH_`)                                                                         | [spec]            | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to)               | spec   |
| <a id="a-18"></a>A-18 | The M3 entropy floor would drop the fixture's database password                                                                  | [spec]            | [M3](HANDOFF.md#m3-matcher-precision), [§11](HANDOFF.md#11-fixtures-and-expected-results)          | spec   |
| <a id="a-19"></a>A-19 | Approvals cached for a time window make "gated" silent                                                                           | [macOS] medium    | [§2 d10](HANDOFF.md#2-decisions-already-made), [M2](HANDOFF.md#m2-collector-parity), [§11](HANDOFF.md#11-fixtures-and-expected-results)  | spec   |
| <a id="a-20"></a>A-20 | Credentials embedded in URLs and `.git/config` remotes were never seen                                                           | [spec]            | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to), [§11](HANDOFF.md#11-fixtures-and-expected-results)          | spec   |
| <a id="a-21"></a>A-21 | Missing credential files: `.yarnrc.yml`, `.bundle/config`, XDG git credentials, glab, Rails master keys                          | [spec]            | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to)               | spec   |
| <a id="a-22"></a>A-22 | SSH agents set by `IdentityAgent` were not checked                                                                               | [spec]            | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to), [M2](HANDOFF.md#m2-collector-parity)           | spec   |
| <a id="a-23"></a>A-23 | Running helpers can hit the network, write refreshed tokens, prompt, or run hostile repo config                                  | [spec]            | [§2 d14](HANDOFF.md#2-decisions-already-made), [M4](HANDOFF.md#m4-helper-inference)       | spec   |
| <a id="a-24"></a>A-24 | Move M6 (content sweep) out of the MVP                                                                                           | [spec]            | [§2 d20](HANDOFF.md#2-decisions-already-made), [§8 Later](HANDOFF.md#later-not-scheduled) | spec   |
| <a id="a-25"></a>A-25 | The persistent HTML report adds risk without adding much over the terminal summary                                               | [spec]            | [§2 d15](HANDOFF.md#2-decisions-already-made), [§5 State](HANDOFF.md#state-on-disk) | spec   |
| <a id="a-26"></a>A-26 | Leaks through fields built from parsed text; HMAC check on all output before writing                                             | [spec]            | [§5](HANDOFF.md#5-architecture), [§6](HANDOFF.md#6-enforcing-the-invariants), [§11](HANDOFF.md#11-fixtures-and-expected-results)      | built   |
| <a id="a-27"></a>A-27 | `~/.exposure-audit` is a ranked list of what to steal, readable by the attacker the tool models                                  | [spec]            | [§2 d16](HANDOFF.md#2-decisions-already-made), [§5 State](HANDOFF.md#state-on-disk) | spec   |
| <a id="a-28"></a>A-28 | Answering a folder-probe prompt permanently changes the permissions being measured                                               | [macOS] high      | [§2 d17](HANDOFF.md#2-decisions-already-made)           | spec   |
| <a id="a-29"></a>A-29 | Reading evicted iCloud or file-provider files downloads them                                                                     | [macOS] medium    | [§3 inv 2](HANDOFF.md#3-invariants), [§5](HANDOFF.md#5-architecture)     | spec   |
| <a id="a-30"></a>A-30 | Snapshot filenames collided within one second and overwrote                                                                      | [spec]            | [§5 State](HANDOFF.md#state-on-disk)         | built   |
| <a id="a-31"></a>A-31 | Exit codes were mentioned but never specified                                                                                    | [spec]            | [§2 d18](HANDOFF.md#2-decisions-already-made)           | built   |
| <a id="a-32"></a>A-32 | Report the install-script controls (npm, Yarn, pnpm, Bun)                                                                        | [spec] medium     | [§2 d19](HANDOFF.md#2-decisions-already-made), [M2](HANDOFF.md#m2-collector-parity)       | spec   |
| <a id="a-33"></a>A-33 | `Environ map[string]Secret` left no way to read the terminal id or `SSH_AUTH_SOCK`; add a five-name `Env.Plain` allowlist | [spec] | [§5 Env](HANDOFF.md#the-env-abstraction) | built |
| <a id="a-34"></a>A-34 | Keychain `SlotID` and `Location` were defined in terms of each other; `SlotID` now comes from `HMAC(kc|service|account)` | [spec] | §5 Data model | spec |
| <a id="a-35"></a>A-35 | The default `.env` sweep would walk Desktop, Documents and iCloud and could raise the prompt decision 17 made opt-in | [spec] | [§5 Collectors](HANDOFF.md#collectors-and-the-runner) | spec |
| <a id="a-36"></a>A-36 | Full Disk Access inference needs Mail, Messages and Safari checked on every run; only TCC folders are opt-in | [spec] | [M2](HANDOFF.md#m2-collector-parity) | spec |
| <a id="a-37"></a>A-37 | Turned-off or inapplicable collectors need a `skipped` status, or `-skip-keychain` looks like a large improvement | [spec] | [§5](HANDOFF.md#5-architecture), [§11](HANDOFF.md#11-fixtures-and-expected-results) | built |
| <a id="a-38"></a>A-38 | SSH public-key fingerprint had no fallback for encrypted PEM or unknown formats | [spec] | [§5 Data model](HANDOFF.md#data-model) | spec |
| <a id="a-39"></a>A-39 | Title of a "Fix first" item spanning several findings was undefined | [spec] | [§5 Data model](HANDOFF.md#data-model) | built |

## Findings from the real run (2026-10-12)

Glenn ran the prototype; agents saw only the terminal summaries.

| ID   | Finding                                                                                                                 | Evidence           | HANDOFF        | Status   |
| ---- | ----------------------------------------------------------------------------------------------------------------------- | ------------------ | -------------- | -------- |
| <a id="r-01"></a>R-01 | Ranking was backwards: `.env` files with four or five cloud-named variables filled the top five; no worm vector made it | [verified]         | [§2 d8](HANDOFF.md#2-decisions-already-made), [§5](HANDOFF.md#5-architecture), [§11](HANDOFF.md#11-fixtures-and-expected-results) | built     |
| <a id="r-02"></a>R-02 | Committed dotenv files should score lower                                                                               | Glenn's decision   | [§2 d9](HANDOFF.md#2-decisions-already-made), [§5](HANDOFF.md#5-architecture), [§11](HANDOFF.md#11-fixtures-and-expected-results) | spec     |
| <a id="r-03"></a>R-03 | The TCC.db check for Full Disk Access gives no result on macOS 27; infer it from Mail, Messages and Safari reach        | [verified]         | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to), [M2](HANDOFF.md#m2-collector-parity)         | spec     |
| <a id="r-04"></a>R-04 | macOS 27 reportedly protects some apps' `Application Support` folders; the prototype's "open" labels are unreliable     | [macOS] unofficial | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to), [§13](HANDOFF.md#13-references)        | spec     |
| <a id="r-05"></a>R-05 | Claude Code exports `CLAUDE_CODE_MESSAGING_TOKEN` to its shells; its scope is unknown                                   | [verified]         | [§2 d11](HANDOFF.md#2-decisions-already-made), [§9 Q3](HANDOFF.md#9-open-questions-for-glenn)  | spec     |
| <a id="r-06"></a>R-06 | Full Disk Access on a terminal may be the most valuable fix, but it was outside the score                               | [spec]             | [§2 d12](HANDOFF.md#2-decisions-already-made), [§5](HANDOFF.md#5-architecture), [M2](HANDOFF.md#m2-collector-parity) | spec     |
| <a id="r-07"></a>R-07 | Real Keychain dumps include partition lists and `mdat`; model partitions and use `mdat` for rotation                    | [verified]         | [§5](HANDOFF.md#5-architecture), [M2](HANDOFF.md#m2-collector-parity)         | spec     |
| <a id="r-08"></a>R-08 | `dump-keychain -a` raised no prompt; 147 items, about 43 classed silent before partitions are modelled                  | [verified]         | [§7](HANDOFF.md#7-what-to-take-from-the-prototype-and-what-not-to)             | verified |
