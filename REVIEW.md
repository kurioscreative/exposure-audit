# Exposure Audit: adversarial review and progress tracker

Companion to `HANDOFF.md`. Reviewed 2026-10-12 against the original HANDOFF.md (commit `735722a`) and `prototype/exposure_audit.py` (v0.1.0, sha256 prefix `b2a9b3a3434feec9`).

The handoff is the spec. This file records why the spec changed, what is still undecided, and how far the build has got. No real paths, report contents, or secret values belong here (HANDOFF section 4).

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
| M0 skeleton and guardrails  | ready       | —                                                               |
| M1 core                     | not started | M0                                                              |
| M2 collector parity         | not started | M1; the Keychain classifier also needs Glenn's sanitized sample |
| M3 matcher precision        | not started | M1                                                              |
| M4 helper inference         | not started | M2 Keychain parser                                              |
| M5 macOS validation (Go)    | not started | M2                                                              |
| M6 content sweep            | post-MVP    | Decision 20                                                     |

### Glenn's to-do list

- [ ] Check System Settings → Privacy & Security → Full Disk Access for Ghostty and every other terminal. The prototype cannot detect this on macOS 27. (R-03, R-06)
- [ ] Find out what `CLAUDE_CODE_MESSAGING_TOKEN` authorizes (HANDOFF §9 Q3). (R-05)
- [ ] During M2: run `exposure-audit -sanitize-keychain-sample`, read the output, commit it to `testdata/`. (R-07)
- [ ] During M5: run the checklist from each terminal, with and without a coding agent. (A-28 and the M5 list)
- [ ] Delete `~/.exposure-audit` left by the prototype once its report is no longer needed. (A-27)

## Decision log

| Date       | Decision                                                                                        | HANDOFF decision | Affects    |
| ---------- | ----------------------------------------------------------------------------------------------- | ---------------- | ---------- |
| 2026-10-12 | Observe macOS with the prototype before building (done the same day)                            | 6                | A-01       |
| 2026-10-12 | Build from source; Go 1.26 is installed through mise                                            | 22               | —          |
| 2026-10-12 | Committed dotenv files score × 0.5                                                              | 9                | R-02       |
| 2026-10-12 | Never execute credential helpers; infer from config plus the Keychain access list               | 14               | A-23, A-09 |
| 2026-10-12 | Score each credential once, highest across locations                                            | 7                | A-14       |
| 2026-10-12 | Drop the multiplier for several secrets in one file                                             | 7                | A-03       |
| 2026-10-12 | Order "Fix first" by class tier, then score                                                     | 8                | R-01       |
| 2026-10-12 | Cached approval windows (1Password CLI and SSH agent) score × 0.5 as `windowed`; never run sudo | 10               | A-19       |
| 2026-10-12 | New `agent` class, weight 5                                                                     | 11               | R-05       |
| 2026-10-12 | Full Disk Access pinned at the top of "Fix first", unscored                                     | 12               | R-06       |
| 2026-10-12 | AWS SSO cache with a `refreshToken` is static                                                   | 13               | A-16       |
| 2026-10-12 | Content sweep (M6) is post-MVP                                                                  | 20               | A-24       |
| 2026-10-12 | HTML report only with `-open`, deleted afterwards                                               | 15               | A-25       |
| 2026-10-12 | History stores no Keychain service or account names                                             | 16               | A-27       |
| 2026-10-12 | Folder probe is opt-in                                                                          | 17               | A-28       |
| 2026-10-12 | Exit codes 0 / 1 / 2                                                                            | 18               | A-31       |
| 2026-10-12 | Unscored Prevention section for install-script controls                                         | 19               | A-32       |
| 2026-10-12 | Passphrase-protected SSH key outside any agent keeps the 0.1 multiplier                         | 21               | —          |

## Findings from the document review

| ID   | Finding                                                                                                                          | Evidence          | HANDOFF          | Status |
| ---- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ---------------- | ------ |
| A-01 | macOS behavior was the main risk but was scheduled last. Run the prototype first                                                 | [spec]            | §2 d6, §7        | done   |
| A-02 | `Secret{b []byte}` leaks under `%s`/`%v` when it is an unexported struct field; the planned unit test would pass anyway          | [verified]        | §5, §6           | spec   |
| A-03 | Fixture expected 6.2 for 6.25; Go's `math.Round` gives 6.3. Multiplier dropped; display rounds half to even                      | [verified]        | §5 Scoring       | spec   |
| A-04 | `html/template` pulls in `net/url` and `net/netip`; the `net` dependency check must match exactly                                | [verified]        | §6               | spec   |
| A-05 | The `ps` chain ends at `tmux`; use `__CFBundleIdentifier` for the context key                                                    | [verified]        | §5 State         | spec   |
| A-06 | Full Disk Access in the context key resets history when it is revoked                                                            | [spec]            | §5 State         | spec   |
| A-07 | Missing history files: `.zsh_sessions/`, `.bash_sessions/`, `.viminfo`                                                           | [verified exists] | §7               | spec   |
| A-08 | `Env.Run` could not set environment or close stdin                                                                               | [spec]            | §5 Env           | spec   |
| A-09 | `Run` returned `[]byte` for helper tokens. Moot: no permitted program prints a secret (decision 14); rule kept for later changes | [spec]            | §5 Env           | spec   |
| A-10 | `Env.Environ map[string]string` put every environment value in a raw string                                                      | [spec]            | §5 Env           | spec   |
| A-11 | `recover` does not catch panics in goroutines a collector starts                                                                 | [spec]            | §5, §6           | spec   |
| A-12 | A collector that ignores `ctx` cannot be stopped; "under a minute" was never enforced                                            | [spec]            | §5, §6           | spec   |
| A-13 | A partial or failed collector made its findings look "resolved"                                                                  | [spec]            | §5, §6, §11      | spec   |
| A-14 | The same credential in several files was scored once per file                                                                    | [spec] + real run | §2 d7, §5        | spec   |
| A-15 | Fingerprint SSH keys by public key so a key file matches the same key in the agent                                               | [spec]            | §5, §11          | spec   |
| A-16 | AWS SSO caches with a `refreshToken` last weeks but were scored as session                                                       | [macOS] medium    | §2 d13, §7       | spec   |
| A-17 | Class-name rules matched inside words (`GH_` in `HIGH_`)                                                                         | [spec]            | §7               | spec   |
| A-18 | The M3 entropy floor would drop the fixture's database password                                                                  | [spec]            | M3, §11          | spec   |
| A-19 | Approvals cached for a time window make "gated" silent                                                                           | [macOS] medium    | §2 d10, M2, §11  | spec   |
| A-20 | Credentials embedded in URLs and `.git/config` remotes were never seen                                                           | [spec]            | §7, §11          | spec   |
| A-21 | Missing credential files: `.yarnrc.yml`, `.bundle/config`, XDG git credentials, glab, Rails master keys                          | [spec]            | §7               | spec   |
| A-22 | SSH agents set by `IdentityAgent` were not checked                                                                               | [spec]            | §7, M2           | spec   |
| A-23 | Running helpers can hit the network, write refreshed tokens, prompt, or run hostile repo config                                  | [spec]            | §2 d14, M4       | spec   |
| A-24 | Move M6 (content sweep) out of the MVP                                                                                           | [spec]            | §2 d20, §8 Later | spec   |
| A-25 | The persistent HTML report adds risk without adding much over the terminal summary                                               | [spec]            | §2 d15, §5 State | spec   |
| A-26 | Leaks through fields built from parsed text; HMAC check on all output before writing                                             | [spec]            | §5, §6, §11      | spec   |
| A-27 | `~/.exposure-audit` is a ranked list of what to steal, readable by the attacker the tool models                                  | [spec]            | §2 d16, §5 State | spec   |
| A-28 | Answering a folder-probe prompt permanently changes the permissions being measured                                               | [macOS] high      | §2 d17           | spec   |
| A-29 | Reading evicted iCloud or file-provider files downloads them                                                                     | [macOS] medium    | §3 inv 2, §5     | spec   |
| A-30 | Snapshot filenames collided within one second and overwrote                                                                      | [spec]            | §5 State         | spec   |
| A-31 | Exit codes were mentioned but never specified                                                                                    | [spec]            | §2 d18           | spec   |
| A-32 | Report the install-script controls (npm, Yarn, pnpm, Bun)                                                                        | [spec] medium     | §2 d19, M2       | spec   |
| A-33 | `Environ map[string]Secret` left no way to read the terminal id or `SSH_AUTH_SOCK`; add a five-name `Env.Plain` allowlist | [spec] | §5 Env | spec |
| A-34 | Keychain `SlotID` and `Location` were defined in terms of each other; `SlotID` now comes from `HMAC(kc|service|account)` | [spec] | §5 Data model | spec |
| A-35 | The default `.env` sweep would walk Desktop, Documents and iCloud and could raise the prompt decision 17 made opt-in | [spec] | §5 Collectors | spec |
| A-36 | Full Disk Access inference needs Mail, Messages and Safari checked on every run; only TCC folders are opt-in | [spec] | M2 | spec |
| A-37 | Turned-off or inapplicable collectors need a `skipped` status, or `-skip-keychain` looks like a large improvement | [spec] | §5, §11 | spec |
| A-38 | SSH public-key fingerprint had no fallback for encrypted PEM or unknown formats | [spec] | §5 Data model | spec |
| A-39 | Title of a "Fix first" item spanning several findings was undefined | [spec] | §5 Data model | spec |

## Findings from the real run (2026-10-12)

Glenn ran the prototype; agents saw only the terminal summaries.

| ID   | Finding                                                                                                                 | Evidence           | HANDOFF        | Status   |
| ---- | ----------------------------------------------------------------------------------------------------------------------- | ------------------ | -------------- | -------- |
| R-01 | Ranking was backwards: `.env` files with four or five cloud-named variables filled the top five; no worm vector made it | [verified]         | §2 d8, §5, §11 | spec     |
| R-02 | Committed dotenv files should score lower                                                                               | Glenn's decision   | §2 d9, §5, §11 | spec     |
| R-03 | The TCC.db check for Full Disk Access gives no result on macOS 27; infer it from Mail, Messages and Safari reach        | [verified]         | §7, M2         | spec     |
| R-04 | macOS 27 reportedly protects some apps' `Application Support` folders; the prototype's "open" labels are unreliable     | [macOS] unofficial | §7, §13        | spec     |
| R-05 | Claude Code exports `CLAUDE_CODE_MESSAGING_TOKEN` to its shells; its scope is unknown                                   | [verified]         | §2 d11, §9 Q3  | spec     |
| R-06 | Full Disk Access on a terminal may be the most valuable fix, but it was outside the score                               | [spec]             | §2 d12, §5, M2 | spec     |
| R-07 | Real Keychain dumps include partition lists and `mdat`; model partitions and use `mdat` for rotation                    | [verified]         | §5, M2         | spec     |
| R-08 | `dump-keychain -a` raised no prompt; 147 items, about 43 classed silent before partitions are modelled                  | [verified]         | §7             | verified |
