<!--
SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
SPDX-License-Identifier: MIT
-->

# Security Policy

crypto11 is a cryptographic library: it brokers access to private key material held in HSMs and
other PKCS#11 tokens. We take reports seriously and would rather hear about a suspected issue than
not. But keep in mind we are in the AI LLM agentic period, and security reports reviewing can become difficult when there are many reports sent in a short period of time.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull
requests.**

Report privately through either channel:

- **[GitHub private vulnerability reporting](https://github.com/eclipse-keypont/crypto11/security/advisories/new)**
  — preferred. It keeps the report, the fix and the advisory in one place.
- **The Eclipse Foundation security team**, at <security@eclipse-foundation.org>. See the
  [Eclipse Foundation Security Policy](https://www.eclipse.org/security/policy/) for the
  Foundation-level process. This is the right channel if the issue spans several Eclipse Keypont
  projects, or if you would rather not report through GitHub.

### What to include

The more of this you can supply, the faster we can confirm and fix:

- A description of the issue and why you believe it has security impact.
- The affected version or commit, and whether `master` is affected.
- The PKCS#11 module and token involved (vendor, product, library/firmware version) — token
  behaviour varies enormously, and an issue that is exploitable against one implementation may be
  inert against another.
- A minimal reproducer, or the sequence of API calls that triggers it.
- Any known workaround or mitigating configuration.
- Whether you intend to disclose publicly, and on what timeline.

Reports in any language are fine, and a partial report is better than none.

## What to expect

We will try are best to let you know when we have confirmed the issue, when a fix lands, and when the advisory is
published. If we conclude the report is not a vulnerability we will explain why, and you are
welcome to push back.

This is a modest project. We do our best to maintain it, but sometimes we lack the time.

## Disclosure

We follow coordinated disclosure. We ask that you give us a reasonable opportunity to release a fix
before disclosing publicly — as a default, 90 days from acknowledgement, or until a fix is
released, whichever comes first. We are happy to agree a different timeline where the situation
warrants it, and we will not use the embargo to sit on a report indefinitely.

When a fix is released we publish a
[GitHub Security Advisory](https://github.com/eclipse-keypont/crypto11/security/advisories) with a
CVE where one is warranted. Reporters are credited by name unless you ask us not to be.

## Supported versions

| Version                                           | Supported                                     |
|---------------------------------------------------|-----------------------------------------------|
| `v2.x` (`github.com/eclipse-keypont/crypto11/v2`) | Yes — active development                      |
| `v1.x` (`github.com/ThalesGroup/crypto11`)        | Security fixes only, at maintainer discretion |
| Anything older                                    | No                                            |

Fixes land on `master` first and ship in the next tagged release. If you need a patch backported to
a v1 line, say so in your report — it is not automatic.

## Scope

**In scope** — anything in this repository that could compromise key material or the integrity of a
cryptographic operation, including:

- Private key material, PINs or other secrets leaking through logs, error messages, returned
  buffers or memory that is not cleared.
- Key or object handles being confused between sessions, or a session pool defect that lets one
  caller act on another's authenticated session.
- Mechanism, parameter or attribute handling that silently weakens an operation — for example
  accepting a padding scheme or key size the caller did not ask for, or failing to enforce an
  attribute the caller set.
- Missing or incorrect validation of data returned by the token, where a malicious or malfunctioning
  token could induce unsafe behaviour in the caller.
- Supply-chain integrity issues in the release pipeline: the signing, SBOM or SLSA provenance
  workflows, or the release artifacts themselves.

**Out of scope:**

- Vulnerabilities in the PKCS#11 module, token or HSM itself. Report those to the vendor. We do
  want to know if crypto11 can defend against them, so tell us anyway if there is something we
  could do.
- Vulnerabilities in dependencies, unless crypto11's use of the dependency is what makes them
  exploitable. Report those upstream; `govulncheck` and Dependabot cover us for the rest.
- Insecure configuration chosen by the caller — for example storing a PIN in a world-readable
  `crypto11.config.json`. If our documentation encourages an insecure pattern, that *is* worth
  reporting.
- Test-only code, example configuration, and the default `1234` PIN used by the SoftHSMv3 test
  harness.

## Verifying what you run

Every tagged release ships a keyless cosign signature, a CycloneDX SBOM and SLSA3 build provenance.
If you need to confirm that the source you are running is what we published, see
[Verifying release artifacts](./README.md#verifying-release-artifacts) in the README.

## Security posture

Every push and pull request runs golangci-lint, `go vet`, govulncheck, CodeQL, secret scanning,
dependency review and an [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/eclipse-keypont/crypto11)
evaluation. These reduce the odds of a defect reaching a release; they do not replace your report.
