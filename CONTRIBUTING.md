<!--
SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
SPDX-License-Identifier: MIT
-->

# Contributing to crypto11

crypto11 is part of [Eclipse KeyPont](https://projects.eclipse.org/projects/technology.keypont).
Contributions are gratefully received — bug reports, test instructions for tokens we can't reach,
documentation fixes and code alike.

**For most changes, just open a pull request.** A bug fix, a test, a documentation correction or
support for a mechanism we already handle elsewhere needs no preamble — the PR *is* the discussion,
and an issue first only means two threads to follow.

**Open an issue first when a rejected PR would waste real work**, which for this library means:

- Changing the public API — a signature change ripples into every dependent.
- Adding a new algorithm, mechanism or PKCS#11 feature area.
- Anything breaking, or anything that changes on-token behaviour or object layout.
- Large refactors touching several files.

That list is short on purpose: it's about protecting your time, not gating contributions. If you're
unsure, open the PR as a draft and ask in it.

Some topics we'd particularly like help with:

- Full test instructions for additional PKCS#11 implementations.
- Coverage for mechanisms only exercised on hardware we don't have.

## Table of contents

- [Provenance: signed commits, the ECA and the DCO](#provenance-signed-commits-the-eca-and-the-dco)
- [Reporting a security vulnerability](#reporting-a-security-vulnerability)
- [Reporting bugs and requesting features](#reporting-bugs-and-requesting-features)
- [Development environment](#development-environment)
- [Running the checks locally](#running-the-checks-locally)
- [Testing against a token](#testing-against-a-token)
- [Fuzzing](#fuzzing)
- [Coding conventions](#coding-conventions)
- [Commit messages](#commit-messages)
- [Opening a pull request](#opening-a-pull-request)
- [Review and merge](#review-and-merge)
- [Code of conduct](#code-of-conduct)

## Provenance: signed commits, the ECA and the DCO

crypto11 guards private key material, so we care about where its code came from. Three
requirements, answering three different questions.

### 1. Cryptographically sign every commit — *who wrote this?*

Every commit must carry a verifiable signature. A `Signed-off-by` line is plain text that anyone
can type; a signature is evidence. We prefer SSH signing — no new keypair if you already push over
SSH:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then add the same key to GitHub as a **signing key** (Settings → SSH and GPG keys → New SSH key →
key type *Signing Key*), so commits show as `Verified`. GPG and S/MIME signing are equally welcome
if that's what you already use. Check your work with `git log --show-signature`, or
`git log --format='%h %G? %an'` — every line should show `G`.

Sign as you go: `git commit -S` per commit, or the `commit.gpgsign` setting above. Retrofitting
signatures onto an existing branch means rewriting it.

### 2. Sign off every commit — *do you have the right to submit it?*

A signature proves identity; it says nothing about rights. The
[Developer Certificate of Origin](https://developercertificate.org/) is the assertion that you may
contribute this code under the project's licence, and it must appear as a trailer:

```
Signed-off-by: Jane Doe <jane.doe@example.com>
```

`git commit -s` adds it. Combine both with `git commit -s -S`, or set
`git config --global format.signOff true` alongside `commit.gpgsign` and forget about it.

### 3. Sign the Eclipse Contributor Agreement — *once, with the Foundation*

Sign the [ECA](https://www.eclipse.org/legal/eca/) once at
<https://accounts.eclipse.org/user/eca>. The Eclipse ECA validation service checks each pull
request automatically.

**The email is what trips people up.** Your commit *author* email, your `Signed-off-by` email and
an email registered on your Eclipse account must all match. If you author commits under a GitHub
noreply address (`12345+user@users.noreply.github.com`), add that address to your Eclipse account
too — otherwise the check fails on commits that are otherwise perfectly valid.

Contributions are licensed under the [MIT License](./LICENSE), matching the rest of the project.
New files carry the same SPDX header the existing sources use:

```go
// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT
```

If your contribution pulls in a new third-party dependency, say so explicitly in the pull request:
dependencies need a license review, an entry in [`NOTICES.md`](./NOTICES.md) (`make notices`) and a
refreshed SBOM (`make sbom`).

## Reporting a security vulnerability

**Do not open a public issue for a security vulnerability.** Report it privately through
[GitHub's private vulnerability reporting](https://github.com/eclipse-keypont/crypto11/security/advisories/new),
or to the Eclipse Foundation security team at <security@eclipse-foundation.org>. See
[SECURITY.md](./SECURITY.md) for the full policy, supported versions and expected response times.

## Reporting bugs and requesting features

Use the issue templates — [bug report](./.github/ISSUE_TEMPLATE/bug_report.md) or
[feature request](./.github/ISSUE_TEMPLATE/feature_request.md). For a bug, the details that
actually shorten the diagnosis are:

- The PKCS#11 module and token you're using (vendor, product, firmware/library version), since
  behaviour varies widely between implementations.
- The crypto11 version (or commit) and `go version`.
- A minimal reproducer, and the full error — including the raw `CKR_*` code where one is reported.
- Whether the same operation succeeds through another PKCS#11 client (e.g. `pkcs11-tool`), which
  tells us quickly whether the bug is ours or the token's.

## Development environment

- **Go** — the version in [`.go-version`](./.go-version) (currently 1.27.1). CI builds against it;
  older toolchains may work but aren't tested.
- **A PKCS#11 token** — optional for a first build, required for meaningful test coverage. See
  [Testing against a token](#testing-against-a-token).
- **Linters and scanners** — optional. Each `make` target that needs one (`lint`, `govulncheck`,
  `notices`, `sbom`) checks for it and prints the `go install` command when it's missing. Make
  sure `$(go env GOPATH)/bin` is on your `PATH`.

Then:

```sh
git clone https://github.com/eclipse-keypont/crypto11.git
cd crypto11
make build
```

## Running the checks locally

The [`Makefile`](./Makefile) targets mirror the CI workflows, so a clean run here is a good
predictor of a green pull request:

| Command | What it runs | CI counterpart |
|---|---|---|
| `make build` | `go build ./...` | `ci.yml` |
| `make vet` | `go vet ./...` | `ci.yml` |
| `make test` | `go test ./...` — fuzz targets only until a token is configured, see below | `ci.yml` |
| `make fuzz` | each fuzz target in turn, 30s apiece (`FUZZTIME`, `FUZZ` to narrow) | `fuzz.yml` (monthly) |
| `make lint` | `golangci-lint run ./...` against [`.golangci.yml`](./.golangci.yml) | `lint.yml` |
| `make lint-fix` | the same, auto-fixing what can be fixed mechanically | — |
| `make govulncheck` | reachability-aware vulnerability scan | `govulncheck.yml` |
| `make notices` | regenerates [`NOTICES.md`](./NOTICES.md) | — |
| `make sbom` | regenerates the CycloneDX SBOM | `release.yml` |

CodeQL, secret scanning, dependency review and the OpenSSF Scorecard gate also run on every pull
request; they need no local setup, but a Scorecard regression (for example, an unpinned GitHub
Action) will block the merge.

## Testing against a token

`go test ./...` passes on a clean clone: with no PKCS#11 module configured, `TestMain` in
[`setup_test.go`](./setup_test.go) narrows the run to the fuzz targets and skips the HSM-backed
suite. **A skipped suite is not a passing suite** — run against a real token before opening a pull
request that touches cryptographic code.

[SoftHSMv3](https://github.com/pqctoday-org/pqctoday-hsm) is the recommended target, and the only
one that covers the PKCS#11 v3.2 / ML-KEM paths — CI runs SoftHSM2, so those paths are only
exercised locally:

```sh
PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so go test ./...
```

`TestMain` creates three ephemeral tokens through the PKCS#11 API, exports the `PKCS11_*` variables
naming them, runs the suite and deletes them. Nothing is written into the working tree, so an
interrupted run leaks nothing. `PKCS11_PIN` overrides the default `1234` user PIN. DSA, DES3, PSS
and HMAC are unsupported by SoftHSMv3 and skip automatically.

Other tokens (AWS CloudHSM, SoftHSM2, nCipher nShield, TPMs) and the `CRYPTO11_SKIP` flags for
mechanisms a token doesn't implement are documented in the README's
[Testing Guidance](./README.md#testing-guidance). **Say in your pull request which token(s) you
tested against** — reviewers can't infer it, and it's the difference between "the tests pass" and
"the tests pass on hardware that supports this mechanism".

### Local configuration

To stop typing the variables on every run, copy a template — both copies are git-ignored:

```sh
cp .env.template .env                     # then set PKCS11_MODULE
set -a; . ./.env; set +a                  # go test does not read .env by itself
```

or, for a file the harness reads on its own:

```sh
cp crypto11.config.json.template crypto11.config.json.local   # then set "Path"
```

VS Code users can point the Go extension at `.env` instead of sourcing it
(`"go.testEnvFile": "${workspaceFolder}/.env"`).

Configuration resolves in three layers, later winning: compiled-in defaults, then a git-ignored
JSON file (`crypto11.config.json.local`, `crypto11.config.json`, or `CRYPTO11_CONFIG_FILE`), then
environment variables. Two families, by design: **`PKCS11_*` says which token to talk to**,
**`CRYPTO11_*` controls how the harness behaves** — follow that split when adding a variable. The
full table is in the README's [Test configuration](./README.md#test-configuration).

Three things that catch people:

- **Write a literal, absolute module path.** Sourcing `.env` in a shell expands `$HOME`, but a
  dotenv loader (VS Code's `go.testEnvFile` among them) hands over `$HOME/...` with the `$` intact;
  the harness expands `$VARS` and `~` as a safety net, not a feature. A relative path is rejected
  outright: a PKCS#11 module is native code that runs on load, and the dynamic linker would resolve
  it against `LD_LIBRARY_PATH`.
- **`CRYPTO11_PROVISION=0` for anything that isn't a throwaway SoftHSM.** With `PKCS11_MODULE` set,
  `TestMain` calls `C_InitToken` to provision its ephemeral tokens. `SOFTHSM2_CONF` confines that to
  a temp directory; CloudHSM, nShield or a TPM would be initialised in place. Select the token you
  already have with `PKCS11_TOKEN_LABEL` — see
  [Ephemeral tokens](./README.md#ephemeral-tokens-and-when-not-to-create-them).
- **Never commit a module path or a PIN**, in a config, a fixture, a workflow or a doc example. A
  reviewer seeing `/home/<someone>/...` in a diff should treat it as a defect. Only the two
  `*.template` files, which hold placeholders, are tracked; `.env`, `crypto11.config.json` and every
  `*.local` file are git-ignored. A `.gitignore` rule does nothing for a file already in the index —
  if `crypto11.config.json` ever reappears as tracked, the fix is `git rm --cached`, not another
  ignore line.

## Fuzzing

[`fuzz_test.go`](./fuzz_test.go) holds native Go fuzz targets for the functions that turn bytes
into values: certificate DER out of `CKA_VALUE`, elliptic curve points and parameters out of
`CKA_EC_POINT` and `CKA_EC_PARAMS`, raw signatures out of `C_Sign`, and the ML-KEM KDF. These are
the package's parsing surface, and the bytes reach them from the token — which anything able to
write to that token decides the contents of.

They need no PKCS#11 module, so they run anywhere:

```sh
make fuzz                          # every target, 30s each
make fuzz FUZZTIME=5m              # a longer budget
make fuzz FUZZ=FuzzKMACEncodings   # one target
```

Each target's seed corpus already runs as part of `make test`, so a PR gets that coverage for
free; the open-ended search runs monthly in [`fuzz.yml`](./.github/workflows/fuzz.yml), and on
demand from the Actions tab.

When a target fails, Go writes the offending input to `testdata/fuzz/<Target>/`. **Commit that
file with the fix** — it becomes a regression case that `go test ./...` replays from then on.
The CI job uploads it as an artifact when the failure happens there.

Adding a target: write it in `fuzz_test.go` (`make fuzz` discovers it by name), seed it with
`f.Add`, and add it to the matrix in `fuzz.yml`. Assert properties rather than exact outputs —
round trips, invariants, agreement between two paths — since a fuzzer's inputs are ones nobody
wrote an expected answer for.

## Coding conventions

- **`gofmt`, and whatever `golangci-lint` says.** The configuration is deliberately strict; don't
  add `//nolint` without a comment explaining why the finding is wrong or unavoidable here.
- **Public API changes are expensive.** crypto11 implements Go's standard `crypto` interfaces; a
  signature change ripples into every dependent. This is one of the few cases worth an issue first
  — see [above](#contributing-to-crypto11) — and always note the impact in the pull request.
- **Errors are wrapped with context, never swallowed.** A raw `CKR_*` from the token should reach
  the caller identifiably — most support requests are diagnosed from exactly that code.
- **Comment the *why*.** The existing sources explain token quirks and spec constraints at the
  point where the code compensates for them; match that. Comments explaining *what* a line does are
  noise, comments explaining which vendor's behaviour forced it are the most valuable text in the
  file.
- **Tests belong with the change.** New mechanisms need coverage that skips gracefully on tokens
  that don't implement them, following the pattern in the existing `*_test.go` files.

## Commit messages

The project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <imperative summary, lower case, no trailing period>

Why the change is needed, what it does, and anything a reviewer would
otherwise have to reconstruct — the token behaviour that motivated it,
alternatives rejected, known limitations. Wrap at 72–80 columns.

Signed-off-by: Jane Doe <jane.doe@example.com>
```

Types in use: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `ci`, `perf`. The scope is
usually the file or subsystem — `rsa`, `keys`, `certificates`, `pool`, `common`.

Commit it with `git commit -s -S` so the message carries the sign-off and the commit carries a
signature — see [Provenance](#provenance-signed-commits-the-eca-and-the-dco).

Recent history is the best style guide (`git log`): commit bodies here are substantial and explain
the reasoning, not just the diff. Credit co-authors with `Co-Authored-By:` trailers, and reference
issues or upstream pull requests by URL.

## Opening a pull request

1. Branch from `master`.
2. Keep the change focused. Unrelated cleanups in the same pull request slow review; send them
   separately.
3. Fill in the [pull request template](./.github/pull_request_template.md) — in particular the
   **Verification**, **Testing** and **User-Facing Change** sections. The `release-note` block
   feeds the release notes; write `NONE` if there's nothing user-facing.
4. Update [`CHANGELOG.md`](./CHANGELOG.md) for any user-visible change (new API, behaviour change,
   bug fix a user could have hit), under the appropriate heading. Internal refactors and test-only
   changes don't need an entry.
5. Update the README if you change installation, configuration or testing procedure.
6. Make sure every commit is **signed and signed off** (`git commit -s -S`) and that CI is green.

Draft pull requests are welcome for work in progress — mark them as drafts so reviewers know not to
spend a full pass on them yet.

## Review and merge

A maintainer reviews every pull request; expect questions, especially about token compatibility and
error handling. Respond to review comments with additional commits rather than force-pushing a
rewritten branch, so reviewers can see what changed — the history is tidied at merge time.

Merges require a green CI run and maintainer approval. Please don't be discouraged by a slow first
response: this is a small project, and correctness in a cryptographic library is worth the wait.

## Code of conduct

This project follows the
[Eclipse Foundation Community Code of Conduct](https://www.eclipse.org/org/documents/Community_Code_of_Conduct.php).
By participating you agree to uphold it. Report unacceptable behaviour to
<codeofconduct@eclipse-foundation.org>.
