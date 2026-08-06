# Changelog

All notable changes to crypto11 are documented in this file. For the full commit-level history see
[GitHub Releases](https://github.com/eclipse-keypont/crypto11/releases).

## v2.0.0 — pkcs11-go, PKCS#11 v3.2 and ML-KEM

v2 is a breaking release (hence the `/v2` module path) driven by three changes: the PKCS#11 binding
was replaced, the config file was renamed, and the API surface was hardened after a security audit.

### Breaking changes

- **PKCS#11 binding replaced**: `miekg/pkcs11` is out, [`eclipse-keypont/pkcs11-go`](https://pkg.go.dev/github.com/eclipse-keypont/pkcs11-go)
  is in. This changes the concrete type behind the public `Attribute` alias.
- Module path is now `github.com/eclipse-keypont/crypto11/v2`.
- The configuration file was renamed to `crypto11.config.json`.
- `FindKeyRSAPairsWithAttributes` is renamed to `FindRSAKeyPairsWithAttributes`, matching every
  other `FindRSA*` finder. The old spelling was the odd one out and made the RSA finders hard to
  find; v2 is the only chance to fix it.
- `FindAllPairedCertificates` now returns the full certificate chain in each `tls.Certificate`,
  where it previously returned the leaf alone. `Certificate[0]` is unchanged; the issuers the token
  also holds follow it, in the order crypto/tls sends them. A caller that assumed exactly one entry
  — or that appended its own intermediates to the result — needs to look again. The motivation is
  that a leaf on its own does not verify at a peer lacking the intermediate, which made the
  returned value unusable for TLS without further work.

### Added

- **PKCS#11 v3.2 support**, via the new pkcs11-go binding.
- **Post-quantum ML-KEM** key generation, encapsulation and decapsulation (ML-KEM 512/768/1024,
  FIPS 203 / `CKM_ML_KEM`) through new `MLKEMEncapsulator` / `MLKEMDecapsulator` interfaces
  (`mlkem.go`).
- `MLKEMDeriveKey`, a KMAC-based key derivation helper for turning ML-KEM shared secrets into
  usable keys.
- `Context.PoolStats`, returning session pool counters — capacity, available, active, in use,
  wait count and wait time — for metrics and diagnostics
  ([#119](https://github.com/eclipse-keypont/crypto11/issues/119), requested by
  [@eriklupander](https://github.com/eriklupander)). It reads in-memory counters only: no PKCS#11
  call, no session taken, safe to call concurrently or on a closed `Context`. The returned
  `PoolStats` is a plain struct, so the vendored `internal/pool` types stay out of the public API.
- `FindAllRSAKeyPairs`, the decryption-capable counterpart of `FindAllKeyPairs`: one call for every
  key pair on the token that can decrypt, returned as `SignerDecrypter`
  ([#112](https://github.com/eclipse-keypont/crypto11/issues/112)). The generic `FindKeyPair` family
  still returns `Signer` — its signatures are unchanged — and now documents where to go for a
  decrypter, as do `Signer` and `SignerDecrypter` themselves.
- `FindAllCertificates`, returning every X.509 certificate on the token
  ([#71](https://github.com/eclipse-keypont/crypto11/pull/71), contributed by
  [@mekpavit](https://github.com/mekpavit)). `FindCertificate` needs an id, label or serial, and
  `FindAllPairedCertificates` only returns certificates that have a matching private key, so a
  caller that knows nothing about the token had no way to list what is on it. Enumeration pages
  through `C_FindObjects` rather than taking a single batch — the original patch stopped at 20
  certificates — restricts itself to `CKC_X_509` objects so a WTLS or attribute certificate is
  skipped instead of failing the call, and shares `FindCertificate`'s null-padding-tolerant DER
  parsing.
- `FindCertificateChain`, returning a certificate together with the issuers above it that the token
  also holds, leaf first ([#91](https://github.com/eclipse-keypont/crypto11/issues/91), proposed by
  [@al1img](https://github.com/al1img) in
  [#83](https://github.com/eclipse-keypont/crypto11/pull/83)). The leaf is located exactly as
  `FindCertificate` locates it; each issuer above it is matched on `CKA_SUBJECT`, falling back to a
  subject key identifier scan. A candidate is accepted only once it is shown to have signed the
  certificate below it, so a token holding two CAs with the same distinguished name — a renewed or
  cross-signed CA — yields the one the chain was really built with. The walk is iterative and skips
  certificates it has already placed, so cross-signed CAs terminate the chain instead of looping,
  and a chain whose root is not on the token is returned short rather than as an error.
- `make release VERSION=x.y.z` target: tags, signs, and pushes a release, triggering a
  SLSA3-attested build.
- `make sbom` target: generates a CycloneDX 1.6 SBOM with the same flags CI uses, so the published SBOM
  is reproducible from the tagged source.
- `make lint`, `make lint-fix`, `make notices`, `make version` Makefile targets.
- `govulncheck` target and CI workflow.

### Security

A dedicated audit found and fixed 7 issues:

- **High**: `UseGCMIVFromHSM` only length-checked the HSM-generated GCM IV instead of copying it
  back to the caller's buffer, making ciphertext undecryptable or risking GCM nonce reuse.
- **Medium**: out-of-bounds unsafe read in `bytesToUlong` when handling attributes shorter than
  `sizeof(CK_ULONG)` (e.g. a 4-byte `CKA_PARAMETER_SET`).
- **Medium**: object handles were left dangling after `Delete`, `Close` was not idempotent
  (a second call could panic via the module refcount), the module cache was keyed inconsistently
  by path, and the PIN was never wiped from memory.
- **Low**: missing bounds checks and unknown-`paramSet` validation in the new ML-KEM code.
- Ported an upstream fix (ThalesGroup PR #135): HMAC sessions were leaked on mid-operation error
  paths and could be returned to the pool twice; key-gen fallback broadened for SoftHSM/Utimaco.

### Fixed

- Key enumeration no longer aborts on a key type the package cannot represent
  ([#68](https://github.com/eclipse-keypont/crypto11/issues/68), reported by
  [@Knacktus](https://github.com/Knacktus) and independently run into by
  [@droppingin](https://github.com/droppingin), who cross-referenced it from
  [#103](https://github.com/eclipse-keypont/crypto11/pull/103) — thank you both for the long wait).
  A single unsupported object — an ML-KEM key pair generated with this release, say — used to make
  `FindAllKeyPairs`, `FindAllKeys`, `FindPrivateKeysWithAttributes`,
  `FindRSAKeyPairsWithAttributes`, `FindRSAPrivateKeysWithAttributes` and
  `FindAllPairedCertificates` fail outright with `unsupported key type: %X`, hiding every other key
  on the token. Such objects are now skipped, like keys with no CKA_ID or no public half.
  `makeRSAPrivateKey`'s error for a non-RSA key also wrapped a nil error, rendering as
  `not an RSA key type: %!w(<nil>)`; it now reports the key type it actually found.
- **Windows**: `bytesToUlong` / `ulongToBytes` no longer assume a `CK_ULONG` is as wide as a Go
  `uint` ([#103](https://github.com/eclipse-keypont/crypto11/pull/103), diagnosed in detail by
  [@droppingin](https://github.com/droppingin) — including the SoftHSM2-for-Windows repro).
  `CK_ULONG` is a C `unsigned long`: 4 bytes under Windows' LLP64 model, 8 under LP64, while Go's
  `uint` is 8 everywhere. Reinterpreting the address of a 4-byte buffer as a `uint` read 4 bytes
  past it, so on Windows every `CK_ULONG` attribute — `CKA_KEY_TYPE`, `CKA_MODULUS_BITS`,
  `CKA_VALUE_LEN` — came back with garbage in its top half. Both conversions now come from the
  binding as `cryptoki.ULongToBytes` / `cryptoki.BytesToULong` (pkcs11-go v1.1.0-rc1), which size
  them from the C type itself: a short attribute is zero-extended, anything past one `CK_ULONG` is
  ignored, and encoding a value too large for the platform's `CK_ULONG` panics rather than silently
  truncating a mechanism parameter.
- Certificates returned in a null-padded `CKA_VALUE` buffer now parse
  ([#106](https://github.com/eclipse-keypont/crypto11/pull/106), reported by
  [@donachan-tesla](https://github.com/donachan-tesla)). Some tokens return the attribute in a
  fixed-size buffer, padded past the end of the certificate, and `x509.ParseCertificate` rejects
  the trailing data — so `FindCertificate` and `FindAllPairedCertificates` failed on those tokens.
  The certificate is now delimited by its own ASN.1 length instead. Note that trimming trailing
  null bytes, as #106 proposed, is not equivalent: the last byte of the signature is effectively
  random, so roughly one certificate in 256 legitimately ends in a null byte and would be
  truncated — padded or not. Trailing bytes that are not null are still an error rather than
  something to discard silently.

### Changed

- **crypto11 no longer contains any cgo of its own.** The `CK_ULONG` conversions were the last
  `import "C"` in the package; they now delegate to `cryptoki.ULongToBytes` / `cryptoki.BytesToULong`,
  added in pkcs11-go v1.1.0-rc1 (which this release requires). The width of a `CK_ULONG` is a
  property of the C ABI, so it belongs in the one package that holds the PKCS#11 headers — keeping a
  second copy here is what let it drift out of step on Windows.
- RSA-PSS signing uses the binding's typed `CK_RSA_PKCS_PSS_PARAMS` (`NewPSSParams`) instead of
  hand-packing three `CK_ULONG`s, matching how OAEP and GCM parameters were already built.
- Internal resource pool (`internal/pool`) reimplemented on native `sync/atomic` typed values,
  removing a hand-rolled 64-bit alignment footgun (relevant to ARM/Raspberry Pi targets).
- Full `golangci-lint` cleanup: ineffassign, prealloc, unconvert, revive exported-comment/
  error-string findings, renamed `errNoCkaId` → `errNoCkaID`, removed deprecated `rand.Seed` calls.
- Test suite hardened to skip gracefully rather than fail when a token doesn't support a given
  mechanism (DSA, HMAC, PSS, etc.), avoid nil-pointer panics, and de-duplicate slot discovery.
- Repository moved from `github.com/ThalesGroup/crypto11` to `github.com/eclipse-keypont/crypto11`
  (Eclipse Foundation donation).

### CI/CD & supply chain

- Unified security/quality pipeline shared across the pkcs11-go / crypto11 / gose projects:
  CodeQL, govulncheck, Gitleaks secret scanning, OpenSSF Scorecard, dependency review, and
  golangci-lint gate every push.
- All third-party GitHub Actions pinned to commit SHAs.
- Tagged releases now produce a signed, **SLSA level 3**-attested source archive
  (via [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) and
  keyless [cosign](https://github.com/sigstore/cosign)) instead of being pushed unsigned — see
  [Verifying release artifacts](./README.md#verifying-release-artifacts) in the README.
- Releases also ship a **CycloneDX 1.6 SBOM** (`crypto11-vX.Y.Z.cdx.json`, generated by
  [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod)), covering the module, its build-time
  dependency graph, the Go standard library and detected licenses. The SBOM is cosign-signed and included
  as a second subject in the SLSA provenance — which is consequently now named
  `crypto11-vX.Y.Z.intoto.jsonl` rather than `crypto11-vX.Y.Z.tar.gz.intoto.jsonl`. See
  [Software Bill of Materials](./README.md#software-bill-of-materials).

## Pre-v2 (ThalesGroup era, v0.1.0 – v1.7.0-rc1)

Originally maintained at `github.com/ThalesGroup/crypto11` (previously `ThalesIgnite/crypto11`),
built on `miekg/pkcs11`. Notable milestones:

- **v1.0.0**: ground-up rewrite of the v0.x API.
- **v1.1.0**: support for finding multiple keys and reading key attributes.
- **v1.2.5**: Thales-proprietary `CKU_CRYPTO_USER` support.
- **v1.3.0**: RSA support for asymmetric decryption.
- **v1.4.1**: PKCS#11 library context reuse via reference counting, allowing multiple contexts to
  the same library.
- **v1.6.3 – v1.6.4**: repository moved to `github.com/eclipse-keypont/crypto11`.
- **v1.6.5**: donated to the Eclipse Foundation.
- **v1.7.0-rc1**: final pre-v2 release candidate, still on `miekg/pkcs11` / Go module path v1.

Full commit history for these releases is available via `git log v0.1.0..v1.7.0-rc1` or the
[GitHub Releases](https://github.com/eclipse-keypont/crypto11/releases) page.
