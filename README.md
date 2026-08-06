# Crypto11

[![Go Reference](https://pkg.go.dev/badge/github.com/eclipse-keypont/crypto11/v2.svg)](https://pkg.go.dev/github.com/eclipse-keypont/crypto11/v2)
[![Build](https://github.com/eclipse-keypont/crypto11/actions/workflows/ci.yml/badge.svg)](https://github.com/eclipse-keypont/crypto11/actions/workflows/ci.yml)
[![Lint](https://github.com/eclipse-keypont/crypto11/actions/workflows/lint.yml/badge.svg)](https://github.com/eclipse-keypont/crypto11/actions/workflows/lint.yml)
[![Secret Scan](https://github.com/eclipse-keypont/crypto11/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/eclipse-keypont/crypto11/actions/workflows/secret-scan.yml)
[![Release](https://github.com/eclipse-keypont/crypto11/actions/workflows/release.yml/badge.svg)](https://github.com/eclipse-keypont/crypto11/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eclipse-keypont/crypto11/badge)](https://scorecard.dev/viewer/?uri=github.com/eclipse-keypont/crypto11)
[![GitHub release](https://img.shields.io/github/v/release/eclipse-keypont/crypto11)](https://github.com/eclipse-keypont/crypto11/releases/latest)
[![Changelog](https://img.shields.io/badge/changelog-v1%20%E2%86%92%20v2-blue)](./CHANGELOG.md)

This is an implementation of the standard Golang crypto interfaces that
uses [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html)
as a backend.

Low-level PKCS#11 (Cryptoki) bindings, including the PKCS#11 v3.2 mechanisms needed for
post-quantum algorithms such as ML-KEM, are provided by
[github.com/eclipse-keypont/pkcs11-go](https://pkg.go.dev/github.com/eclipse-keypont/pkcs11-go).
crypto11 builds the familiar `crypto.Signer` / `crypto.Decrypter` Go interfaces on top of it.

**v2** is a breaking release: the PKCS#11 binding moved to
[pkcs11-go](https://pkg.go.dev/github.com/eclipse-keypont/pkcs11-go), bringing PKCS#11 v3.2 and post-quantum
ML-KEM key support, alongside a full lint/vet cleanup and a security-hardening pass. See
[CHANGELOG.md](./CHANGELOG.md) for a summary of what changed between v1 and v2, or
[Releases](https://github.com/eclipse-keypont/crypto11/releases) for the full commit-level history.

This repository is built with a hardened GitHub Actions pipeline: golangci-lint, govulncheck, CodeQL, secret
scanning, dependency review, and an OpenSSF Scorecard rating gate every push, and tagged releases ship a signed,
SLSA3-attested source archive plus a signed [CycloneDX SBOM](#software-bill-of-materials) rather than just being
pushed — see [Verifying release artifacts](#verifying-release-artifacts) below for what ships and how to check it.

# Part of Eclipse Keypont

crypto11 is part of [Eclipse Keypont](https://projects.eclipse.org/projects/technology.keypont), alongside
[gose](https://github.com/eclipse-keypont/gose) and [pkcs11-go](https://github.com/eclipse-keypont/pkcs11-go).
*Keypont* — "key" plus the French *pont* ("bridge") — reflects the project's goal: bridging Go
applications to cryptographic keys held in HSMs and other PKCS#11-backed hardware.

# Supported Algorithms

## Asymmetric keys

| Algorithm | Key generation |     Signing      |    Decryption     | Notes                                    |
|-----------|:--------------:|:----------------:|:-----------------:|------------------------------------------|
| RSA       |       ✓        | PKCS#1 v1.5, PSS | PKCS#1 v1.5, OAEP | Via `crypto.Signer` / `crypto.Decrypter` |
| ECDSA     |       ✓        |        ✓         |         —         | Via `crypto.Signer`                      |
| DSA       |       ✓        |        ✓         |         —         | Via `crypto.Signer`                      |

To verify signatures or encrypt messages, retrieve the public key and do it in software.

## Post-quantum keys (PKCS#11 v3.2)

| Algorithm   | Key generation | Encapsulation | Decapsulation | Notes                                  |
|-------------|:--------------:|:-------------:|:-------------:|----------------------------------------|
| ML-KEM 512  |       ✓        |       ✓       |       ✓       | FIPS 203 / PKCS#11 v3.2 (`CKM_ML_KEM`) |
| ML-KEM 768  |       ✓        |       ✓       |       ✓       | FIPS 203 / PKCS#11 v3.2 (`CKM_ML_KEM`) |
| ML-KEM 1024 |       ✓        |       ✓       |       ✓       | FIPS 203 / PKCS#11 v3.2 (`CKM_ML_KEM`) |

ML-KEM uses the `MLKEMEncapsulator` / `MLKEMDecapsulator` interfaces (not `crypto.Signer`).
Requires a PKCS#11 v3.2-capable token such as [SoftHSMv3](https://github.com/pqctoday-org/pqctoday-hsm).

## Symmetric keys

| Algorithm | Key sizes         | Modes    | Notes                                                       |
|-----------|-------------------|----------|-------------------------------------------------------------|
| AES       | 128, 192, 256 bit | CBC, GCM | `cipher.Block`, `cipher.BlockMode`, `BlockModeCloser`, AEAD |
| DES3      | 192 bit           | CBC      | Token support varies                                        |

## Other

| Feature                  | Notes                                           |
|--------------------------|-------------------------------------------------|
| X.509 certificates       | Import and retrieval                            |
| HMAC                     | Token support varies (not available on SoftHSM) |
| Random number generation | Via `io.Reader`                                 |

Signing is done through the
[crypto.Signer](https://golang.org/pkg/crypto/#Signer) interface and
decryption through
[crypto.Decrypter](https://golang.org/pkg/crypto/#Decrypter).

See [the documentation](https://godoc.org/github.com/eclipse-keypont/crypto11/v2) for details of various limitations,
especially regarding symmetric crypto.


# Installation

crypto11 requires Go 1.25 or later (see the `go` directive in `go.mod`). Install the library by running:

> **Note on Go version policy**
>
> crypto11 is a library. Bumping the `go` directive in `go.mod` raises the **minimum** Go version required by every project that imports it, which can break consumers still on older toolchains.
>
> To avoid this, we follow a two-directive pattern:
> - `go X.Y.0` — the **minimum** Go version consumers need (kept conservative).
> - `toolchain go X.Y.Z` — the **recommended** toolchain used by maintainers (tracks the latest patch release).
>
> This lets projects on older Go versions still import crypto11, while maintainers can develop and test with the latest toolchain.
> See [#137](https://github.com/eclipse-keypont/crypto11/issues/137) for context.

```sh
go get github.com/eclipse-keypont/crypto11/v2
```

The crypto11 library needs to be configured with information about your PKCS#11 installation. This is either done
programmatically
(see the `Config` struct in [the documentation](https://godoc.org/github.com/eclipse-keypont/crypto11/v2)) or via a
configuration
file. The configuration file is a JSON representation of the `Config` struct.

A minimal configuration file looks like this:

```json
{
  "Path": "/usr/lib/softhsm/libsofthsm2.so",
  "TokenLabel": "token1",
  "Pin": "password"
}
```

- `Path` points to the library from your PKCS#11 vendor.
- `TokenLabel` is the `CKA_LABEL` of the token you wish to use.
- `Pin` is the password for the `CKU_USER` user.
- `UseGCMIVFromHSM` generates the IV for GCM mechanism from the HSM

# Build

This package is using CGo for cryptographic packages.  
Enable CGo before building Crypto11 :

```sh
go env -w CGO_ENABLED=1
go build
```

A `Makefile` wraps the common developer commands:

| Target                       | Description                                                                               |
|------------------------------|-------------------------------------------------------------------------------------------|
| `make build`                 | `go build ./...`                                                                          |
| `make test`                  | `go test ./...` (see [Testing Guidance](#testing-guidance) below for HSM-backed coverage) |
| `make lint`                  | Runs `golangci-lint` (v2) against `.golangci.yml`, same checks as CI                      |
| `make lint-fix`              | Runs `golangci-lint` with `--fix` for mechanically-fixable findings                       |
| `make notices`               | Regenerates [`NOTICES.md`](./NOTICES.md) via `go-licenses`                                |
| `make version`               | Prints the most recent git tag                                                            |
| `make release VERSION=x.y.z` | Creates a signed `vx.y.z` tag and pushes it, triggering the release workflow              |

# Testing Guidance

## Disabling tests

To disable specific tests, set the environment variable `CRYPTO11_SKIP=<flags>` where `<flags>` is a comma-separated
list of the following options:

* `CERTS` - disables certificate-related tests. Needed for AWS CloudHSM, which doesn't support certificates.
* `OAEP_LABEL` - disables RSA OAEP encryption tests that use source data encoding parameter (also known as a 'label'
  in some crypto libraries). Needed for AWS CloudHSM.
* `DSA` - disables DSA tests. Needed for AWS CloudHSM (and any other tokens not supporting DSA).

## Testing with SoftHSMv3 (recommended)

[SoftHSMv3](https://github.com/pqctoday-org/pqctoday-hsm) supports PKCS#11 v3.2 and is required for
ML-KEM and other post-quantum tests. Token provisioning is fully automated:

```sh
PKCS11_MODULE=/path/to/libsofthsmv3.so go test ./...
```

Override the user PIN (default `1234`):

```sh
PKCS11_MODULE=/path/to/libsofthsmv3.so PKCS11_PIN=mypin go test ./...
```

`TestMain` in `setup_test.go` creates three ephemeral tokens (`crypto11-test`, `token1`, `token2`)
via the PKCS#11 API, writes a temporary `config` file, runs all tests, then cleans up. No
external tools or manual token setup are required.

DSA, DES3, PSS, and HMAC are not supported by SoftHSMv3 and those tests are automatically skipped.

## Unit test on one file

```sh
export DEPENDENCIES="rand.go attributes.go hmac.go crypto11.go common.go keys.go rsa.go certificates.go ecdsa.go blockmode.go sessions.go aead.go dsa.go symmetric.go mlkem.go common_test.go"
go test blockmode_test.go $DEPENDENCIES
```

Remote debug :

```sh
dlv test --headless --listen=:2345 --api-version=2 --accept-multiclient blockmode_test.go $DEPENDENCIES
```

## Testing with AWS CloudHSM

A minimal configuration file for CloudHSM will look like this:

```json
{
  "Path": "/opt/cloudhsm/lib/libcloudhsm_pkcs11_standard.so",
  "TokenLabel": "cavium",
  "Pin": "username:password",
  "UseGCMIVFromHSM": true
}
```

To run the test suite you must skip unsupported tests:

```sh
CRYPTO11_SKIP=CERTS,OAEP_LABEL,DSA go test -v
```

Be sure to take note of the supported mechanisms, key types and other idiosyncrasies described at
https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html. Here's a collection of things we
noticed when testing with the v2.0.4 PKCS#11 library:

- 1024-bit RSA keys don't appear to be supported, despite what `C_GetMechanismInfo` tells you.
- The `CKM_RSA_PKCS_OAEP` mechanism doesn't support source data. I.e. when constructing a `CK_RSA_PKCS_OAEP_PARAMS`,
  one must set `pSourceData` to `NULL` and `ulSourceDataLen` to zero.
- CloudHSM will generate it's own IV for GCM mode. This is described in their documentation, see footnote 4 on
  https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html.
- It appears that `CKA_ID` values must be unique, otherwise you get a `CKR_ATTRIBUTE_VALUE_INVALID` error.
- Very rapid session opening can trigger the following error:
  ```text
  C_OpenSession failed with error CKR_ARGUMENTS_BAD : 0x00000007
  HSM error 8c: HSM Error: Already maximum number of sessions are issued
  ```

## Testing with SoftHSM2

[SoftHSMv2](https://github.com/softhsm/SoftHSMv2) covers all classical algorithms but does **not**
support ML-KEM or other PKCS#11 v3.2 mechanisms (those tests will be skipped automatically via
`skipIfMechUnsupported`).

To set up a slot:

```sh
$ cat softhsm2.conf
directories.tokendir = /home/rjk/go/src/github.com/eclipse-keypont/crypto11/tokens
objectstore.backend = file
log.level = INFO
$ mkdir tokens
$ export SOFTHSM2_CONF=`pwd`/softhsm2.conf
$ softhsm2-util --init-token --slot 0 --label test
=== SO PIN (4-255 characters) ===
Please enter SO PIN: ********
Please reenter SO PIN: ********
=== User PIN (4-255 characters) ===
Please enter user PIN: ********
Please reenter user PIN: ********
The token has been initialized.
```

The configuration looks like this:

```json
{
  "Path" : "/usr/lib/softhsm/libsofthsm2.so",
  "TokenLabel": "test",
  "Pin" : "password"
}
```

OAEP is only partial and HMAC is unsupported on SoftHSMv2, so expect test skips.

## Testing with nCipher nShield

In all cases, it's worth enabling nShield PKCS#11 log output:

```sh
export CKNFAST_DEBUG=2
```

To protect keys with a 1/N operator cardset:

```json
{
  "Path" : "/opt/nfast/toolkits/pkcs11/libcknfast.so",
  "TokenLabel": "rjk",
  "Pin" : "password"
}
```

You can also identify the token by serial number, which in this case
means the first 16 hex digits of the operator cardset's token hash:

```json
{
  "Path" : "/opt/nfast/toolkits/pkcs11/libcknfast.so",
  "TokenSerial": "1d42780caa22efd5",
  "Pin" : "password"
}
```

A card from the cardset must be in the slot when you run `go test`.

To protect keys with the module only, use the 'accelerator' token:

```json
{
  "Path" : "/opt/nfast/toolkits/pkcs11/libcknfast.so",
  "TokenLabel": "accelerator",
  "Pin" : "password"
}
```

(At time of writing) GCM is not implemented, so expect test skips.

## Testing with a TPM and PKCS11

You must know that tpm2-pkcs11 is much more limited than other libraries like softhsm2 for cryptographic operations.  
The absence of the `C_GenerateKey` function in the tpm2-pkcs11 library is one example of the limitations.  
However, some of the tests have been modified to support the tpm2-pkcs11 library's specificities.

To test with a TPM, you need to :

- install a virtual TPM or use a TPM on your machine
- install the `libtpm2_pkcs11` library
- create all the keys you need for the unit tests in the TPM (since C_Generate key is not supported)

Configure :

```json
{
  "Path": "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
  "TokenLabel": "mylabel",
  "Pin": "mypin"
}
```

Fine tune the unit tests to use the keys you created in the previous step.  
Beware that a lot of unit tests may fail otherwise. You must fine-tune your usecase for a TPM usage.

# Limitations

* The [PKCS1v15DecryptOptions SessionKeyLen](https://golang.org/pkg/crypto/rsa/#PKCS1v15DecryptOptions) field
  is not implemented and an error is returned if it is nonzero.
  The reason for this is that it is not possible for crypto11 to guarantee the constant-time behavior in the
  specification.
  See [issue #5](https://github.com/eclipse-keypont/crypto11/issues/5) for further discussion.
* Symmetric crypto support via [cipher.Block](https://golang.org/pkg/crypto/cipher/#Block) is very slow.
  You can use the `BlockModeCloser` API
  (over 400 times as fast on my computer)
  but you must call the Close()
  interface (not found in [cipher.BlockMode](https://golang.org/pkg/crypto/cipher/#BlockMode)).
  See [issue #6](https://github.com/eclipse-keypont/crypto11/issues/6) for further discussion.
* Unit tests may interfere between them. You should fine tune and select the Go test file you want to run, one at a
  time.

# Verifying release artifacts

Each GitHub Release ships a deterministic source archive plus everything needed to verify it without trusting
GitHub. For a release `vX.Y.Z` you'll find:

| Asset | Purpose |
|-------|---------|
| `crypto11-vX.Y.Z.tar.gz` | The source archive, built with `git archive` from the tagged commit |
| `crypto11-vX.Y.Z.tar.gz.sha256` | SHA-256 checksum of the archive |
| `crypto11-vX.Y.Z.tar.gz.cosign.bundle` | Keyless [cosign](https://github.com/sigstore/cosign) signature (signed via GitHub Actions OIDC — no private key involved) |
| `crypto11-vX.Y.Z.cdx.json` | [CycloneDX](https://cyclonedx.org/) 1.6 SBOM of the module — see [Software Bill of Materials](#software-bill-of-materials) |
| `crypto11-vX.Y.Z.cdx.json.sha256` | SHA-256 checksum of the SBOM |
| `crypto11-vX.Y.Z.cdx.json.cosign.bundle` | Keyless cosign signature of the SBOM |
| `crypto11-vX.Y.Z.intoto.jsonl` | [SLSA3](https://slsa.dev/) build provenance covering **both** the archive and the SBOM, produced by [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) |

Download all assets for the release you want to verify:

```sh
gh release download vX.Y.Z --repo eclipse-keypont/crypto11
```

**1. Verify the checksums**

```sh
sha256sum -c crypto11-vX.Y.Z.tar.gz.sha256
sha256sum -c crypto11-vX.Y.Z.cdx.json.sha256
```

**2. Verify the cosign signatures** (requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/))

```sh
for f in crypto11-vX.Y.Z.tar.gz crypto11-vX.Y.Z.cdx.json; do
  cosign verify-blob \
    --bundle "$f.cosign.bundle" \
    --certificate-identity-regexp '^https://github\.com/eclipse-keypont/crypto11/\.github/workflows/release\.yml@refs/tags/v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$f"
done
```

**3. Verify the SLSA provenance** (requires [slsa-verifier](https://github.com/slsa-framework/slsa-verifier))

The provenance has two subjects — the archive and the SBOM — so verify both in one call:

```sh
slsa-verifier verify-artifact \
  --provenance-path crypto11-vX.Y.Z.intoto.jsonl \
  --source-uri github.com/eclipse-keypont/crypto11 \
  --source-tag vX.Y.Z \
  crypto11-vX.Y.Z.tar.gz crypto11-vX.Y.Z.cdx.json
```

**4. Verify the git tag itself** — release tags are GPG/SSH-signed by `make release` (`git tag -s`):

```sh
git verify-tag vX.Y.Z
```

`go get` consumers don't need any of this — they fetch source through the Go module proxy and verify it via
`go.sum` / `sum.golang.org`. These assets exist for auditors and to satisfy OpenSSF Scorecard's Signed-Releases
check.

# Software Bill of Materials

Every release ships a [CycloneDX](https://cyclonedx.org/) 1.6 SBOM (`crypto11-vX.Y.Z.cdx.json`), generated with
[`cyclonedx-gomod`](https://github.com/CycloneDX/cyclonedx-gomod) and signed and attested exactly like the source
archive (see [Verifying release artifacts](#verifying-release-artifacts)). It describes:

* the `crypto11` component itself, typed as a **library**, with its module path, version and VCS reference;
* its build-time dependency graph — `pkcs11-go` and `pkg/errors` — as `pkg:golang/...` PackageURLs;
* the **Go standard library** as a component (`pkg:golang/std@goX.Y.Z`), so stdlib CVEs stay visible to SBOM
  consumers, matching what `govulncheck` covers;
* detected **licenses**, recorded as CycloneDX evidence rather than assertions (detection is heuristic).

Test-only dependencies (`testify` and friends) are deliberately excluded: they are not part of what a consumer of
the library links against, and including them produces false positives in downstream vulnerability scanners.

Regenerate the SBOM yourself with the same flags CI uses:

```sh
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0
make sbom          # writes crypto11.cdx.json
```

The SBOM is generated with `-noserial -notimestamp`, so it is byte-reproducible from the tagged commit — checking
out `vX.Y.Z` and running `make sbom` on linux/amd64 yields the same content as the published artifact (the
`goos`/`goarch` PackageURL qualifiers make the output platform-specific).

Feed it into whatever consumes CycloneDX — for example
[Dependency-Track](https://dependencytrack.org/), [osv-scanner](https://github.com/google/osv-scanner)
(`osv-scanner scan source --sbom crypto11-vX.Y.Z.cdx.json`) or `grype sbom:crypto11-vX.Y.Z.cdx.json`.

# Contributions

Contributions are gratefully received. Before beginning work on sizeable changes, please open an issue first to
discuss.

Here are some topics we'd like to cover:

* Full test instructions for additional PKCS#11 implementations.

# Security

To report a vulnerability, **do not open a public issue** — use
[private vulnerability reporting](https://github.com/eclipse-keypont/crypto11/security/advisories/new) or contact
the Eclipse Foundation security team. See [`SECURITY.md`](./SECURITY.md) for the full policy, supported versions
and scope.

# Third-party notices

[`NOTICES.md`](./NOTICES.md) lists all third-party dependency licenses and is auto-generated via `make notices` (requires [`go-licenses`](https://github.com/google/go-licenses)).

# Vulnerability check

```sh
$ govulncheck ./...

Scanning your code and 112 packages across 5 dependent modules for known vulnerabilities...

No vulnerabilities found.
```