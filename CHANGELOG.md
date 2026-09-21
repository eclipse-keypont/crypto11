# Changelog

All notable changes to crypto11 are documented in this file. For the full commit-level history see
[GitHub Releases](https://github.com/eclipse-keypont/crypto11/releases).

## v2.0.0 — pkcs11-go, PKCS#11 v3.2 and ML-KEM

v2 is a breaking release (hence the `/v2` module path) driven by three changes: the PKCS#11 binding
was replaced, the config file was renamed, and the API surface was hardened after a security audit.

### Breaking changes

- `ConfigureFromFile` refuses a configuration file that contains a `Pin` and is readable by its
  group or by others (mode `& 0077 != 0`; not checked on Windows). A `chmod 600` on the file, or
  moving the PIN out of it (`Config.PinFunc`, an environment variable), is the fix.
- Generated private and secret keys default to `CKA_PRIVATE=true`. A template that sets
  `CKA_PRIVATE` explicitly is honoured; a Context with `LoginNotSupported` keeps the token's
  default.
- `GetAttributes`, `GetAttribute`, `GetPubAttributes` and `GetPubAttribute` return `errForeignKey`
  for a key obtained through a different Context.
- `Signer.Sign` with PKCS#1 v1.5 rejects a `crypto.Hash` it has no DigestInfo prefix for, and a
  digest whose length is not `hash.Size()`; `crypto.Hash(0)` still signs the input bare.
- `Config.UserType` must be `DefaultUserType` (`CKU_USER`) or `CryptoUser`; any other value is
  rejected by `Configure`.
- `github.com/pkg/errors` is no longer a dependency. Error strings are unchanged.
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
- `Config.PinFunc`, a callback that supplies the PIN as bytes to `Configure`, which wipes them as
  soon as the token has been logged into. For callers who would rather never hold the PIN in a
  Go `string`, which cannot be wiped.
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
- Native Go **fuzz targets** for the token-parsing surface (`fuzz_test.go`): certificate DER out
  of `CKA_VALUE`, EC points and parameters out of `CKA_EC_POINT` / `CKA_EC_PARAMS`, raw signatures
  out of `C_Sign`, and the ML-KEM KDF encodings. They need no token, their seed corpora run under
  `go test ./...`, and `make fuzz` (`FUZZTIME`, `FUZZ` to narrow) or the monthly `fuzz` workflow
  runs the open-ended search.
- `.env.template` and `crypto11.config.json.template`, the committed placeholders for local test
  configuration. The real `.env`, `crypto11.config.json` and every `*.local` file are git-ignored.
- `CONTRIBUTING.md`: provenance requirements (signed commits, DCO, ECA), how to run the checks and
  the suite against a token, and the no-secrets rule for test configuration.

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

A second round, cross-checking that audit against an automated one (Synapse) and verifying every
finding against the code, fixed 27 more. By theme:

- **Token output is validated.** The DSA public key a token returns must have prime `p`/`q`,
  `q | p-1` and `g`, `y` of order `q` — Go's `dsa.Verify` accepts `(1, 1)` as a signature over
  anything under a `G = Y = 1` key. A generated ECDSA key must be on the curve that was asked
  for, a generated DSA key under the parameters that were asked for, an ML-KEM key pair's
  reported parameter set must be the one in the template. A MAC from `C_SignFinal` must be the
  size its mechanism produces (the MD5 size in the table was wrong, 20 for 16). An ML-KEM shared
  secret that comes back empty is an error, not an empty secret.
- **Keys are what they say they are.** A label-only private key with no matching public object
  was paired with the first public key of the right type on the token, giving a `Signer` whose
  `Public()` it could not sign for; the certificate fallback matched every certificate without a
  `CKA_ID` the same way. `GetAttributes`/`GetPubAttributes` resolved a key's handle against
  whichever Context they were called on; a key from another Context is now `errForeignKey`.
  `signPKCS1v15` refuses a hash it has no DigestInfo for (it used to sign the bare digest under
  that name) and a digest of the wrong size; `decryptOAEP` honours `OAEPOptions.MGFHash`
  instead of deriving MGF1 from `Hash`; PKCS#1 v1.5 decryption failures are reported as
  `rsa.ErrDecryption` rather than the token's padding verdict, and `Decrypt` documents the
  oracle a caller of v1.5 takes on.
- **Secure-by-default templates.** Generated private and secret keys carry `CKA_PRIVATE=true`
  unless the caller's template says otherwise (or the Context is `LoginNotSupported`);
  `CKA_SENSITIVE`/`CKA_EXTRACTABLE` protect a key's value, not its use. A key pair whose
  generation fails after `C_GenerateKeyPair` — a public key that cannot be exported, a curve
  mismatch — is destroyed rather than left on the token; an unexportable curve is refused before
  anything is created.
- **Lifecycle.** A token advertising one read/write session made `Configure` panic (the pool
  constructor rejects a zero capacity); it is an error now. A failed `C_Login` leaked the
  persistent session whenever another Context shared the module. `UserType` values other than
  `CKU_USER` and `CryptoUser` were silently logged in as `CryptoUser`; they are rejected.
  Sessions the token declares dead (`CKR_SESSION_HANDLE_INVALID`, `CKR_DEVICE_ERROR`, a stuck
  `CKR_OPERATION_ACTIVE`, ...) are closed and replaced instead of returned to the pool.
  `Context.Close` now takes a write lock that every operation holds for reading while it has a
  session, so the closed check and the session grab are one step, and `Close` waits for
  operations in flight; `moduleCtx` refcount drift is an error from `Close` rather than a panic.
- **Panics that could not be caught.** `hash.Hash.Reset` on an HMAC whose reinitialization
  failed returned the previous message's MAC from the next `Sum`; the hash is now dead instead.
  The runtime finalizer on a CBC block mode created without a Closer called `Close`, which
  panics on a token error — on the finalizer goroutine, where nothing can recover it. The
  issuer walk in `FindCertificateChain`/`FindAllPairedCertificates` is bounded (16) and scans the
  token at most once per chain, where a chain of _N_ certificates could cost _N_ full scans.
- **Secret lifetime.** The KMAC key encoding in `MLKEMDeriveKey` no longer leaves append-time
  copies of the shared secret for the garbage collector; `MLKEMSharedSecret.Bytes` wipes the
  binding's copy after handing the caller its own; CBC decryption wipes the binding's plaintext
  buffer; `AttributeSet.String` redacts `CKA_VALUE`, the RSA private components and
  vendor-defined attributes. `Config.PinFunc` supplies the PIN as bytes that are wiped right after
  login, for callers who would rather never hold it in a `string`; `ConfigureFromFile` refuses a
  file that holds a `Pin` and is readable by anyone but its owner.

`SECURITY.md` documents how to report a vulnerability privately — GitHub private vulnerability
reporting or the Eclipse Foundation security team — and which versions receive fixes.

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
  binding as `cryptoki.ULongToBytes` / `cryptoki.BytesToULong` (pkcs11-go v1.1.1), which size
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
- RSA-PSS signing with `rsa.PSSSaltLengthAuto` now succeeds instead of returning
  `errUnsupportedRSAOptions` ([#96](https://github.com/eclipse-keypont/crypto11/pull/96), by
  [@maraino](https://github.com/maraino), whose calculation and worked example this follows). The
  salt is resolved to the largest the modulus can carry — `(bits-1+7)/8 - hLen - 2`, the value
  `crypto/rsa` picks — so the zero-valued `PSSOptions.SaltLength` that `crypto.Signer` callers
  commonly pass produces a signature verifiers accept. Unlike #96, the arithmetic is done in `int`
  and a modulus too small for the hash reports `rsa.ErrMessageTooLong` rather than wrapping to a
  salt length near 2⁶⁴. `Auto` is still rejected when the key's public half is not an
  `*rsa.PublicKey`, since there is no modulus to size the salt from.

### Changed

- **crypto11 no longer contains any cgo of its own.** The `CK_ULONG` conversions were the last
  `import "C"` in the package; they now delegate to `cryptoki.ULongToBytes` / `cryptoki.BytesToULong`,
  added in pkcs11-go v1.1.0. This release requires v1.1.1, which also carries the binding's own
  fixes for the Synapse security findings
  ([eclipse-keypont/pkcs11-go#15](https://github.com/eclipse-keypont/pkcs11-go/pull/15)). The
  width of a `CK_ULONG` is a property of the C ABI, so it belongs in the one package that holds the
  PKCS#11 headers — keeping a second copy here is what let it drift out of step on Windows.
- RSA-PSS signing uses the binding's typed `CK_RSA_PKCS_PSS_PARAMS` (`NewPSSParams`) instead of
  hand-packing three `CK_ULONG`s, matching how OAEP and GCM parameters were already built.
- Internal resource pool (`internal/pool`) reimplemented on native `sync/atomic` typed values,
  removing a hand-rolled 64-bit alignment footgun (relevant to ARM/Raspberry Pi targets).
- Full `golangci-lint` cleanup: ineffassign, prealloc, unconvert, revive exported-comment/
  error-string findings, renamed `errNoCkaId` → `errNoCkaID`, removed deprecated `rand.Seed` calls.
- Test suite hardened to skip gracefully rather than fail when a token doesn't support a given
  mechanism (DSA, HMAC, PSS, etc.), tolerate pre-existing token objects, avoid nil-pointer panics,
  and de-duplicate slot discovery. Integration testing moved to
  [SoftHSMv3](https://github.com/pqctoday-org/pqctoday-hsm), which is what makes the PKCS#11 v3.2
  and ML-KEM paths testable; SoftHSM2 and hardware tokens self-skip what they lack.
- Test configuration is resolved from compiled-in defaults, then a git-ignored JSON file
  (`crypto11.config.json.local`, `crypto11.config.json`, or `CRYPTO11_CONFIG_FILE`), then the
  environment, and is never written back into the tree. `setup_test.go` used to write the module
  path and PIN into a tracked `crypto11.config.json` and restore it only on a clean exit, so an
  interrupted run left both one `git add -A` away from a commit; it now exports the names of its
  ephemeral tokens as variables instead. Variables follow one rule — `PKCS11_*` says which token
  to talk to, `CRYPTO11_*` controls the harness — and `CRYPTO11_PROVISION=0` skips the
  `C_InitToken` provisioning for a module that is not a throwaway SoftHSM. With nothing configured,
  `go test ./...` narrows to the fuzz targets and passes on a fresh clone.
- Repository moved from `github.com/ThalesGroup/crypto11` to `github.com/eclipse-keypont/crypto11`
  (Eclipse Foundation donation). SPDX license headers added, naming Thales Group and the Eclipse
  Foundation KeyPont project maintainers as copyright holders — `LICENSE` likewise — and
  `NOTICES.md` generated from the dependency graph.
- `go.mod` follows the two-directive policy adopted on `master` in
  [#137](https://github.com/eclipse-keypont/crypto11/issues/137): `go 1.25.0` is the minimum a
  consumer needs — lowered from `go 1.26.1` in v1.7.0-rc1, since a library's `go` directive is a
  floor imposed on every importer — and `toolchain go1.27.1` is what maintainers build and test
  with. `.go-version` tracks the toolchain.

### CI/CD & supply chain

- Unified security/quality pipeline shared across the pkcs11-go / crypto11 / gose projects:
  CodeQL, govulncheck, Gitleaks secret scanning, OpenSSF Scorecard, dependency review, and
  golangci-lint gate every push.
- All third-party GitHub Actions pinned to commit SHAs.
- Travis CI configuration removed; it was no longer in use.
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
