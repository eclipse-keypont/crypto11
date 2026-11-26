# Changelog

All notable changes to crypto11 are documented in this file. For the full commit-level history see
[GitHub Releases](https://github.com/eclipse-keypont/crypto11/releases).

## Unreleased

### Security

- When the Context logs in, the secret-key, private-key and key-pair finders now match only
  private objects (`CKA_PRIVATE = true`), unless the caller's attribute set names
  `CKA_PRIVATE` itself. Only a logged-in user can create a private object, whereas many tokens
  let any session create public ones, so a public object carrying the requested `CKA_ID` or
  `CKA_LABEL` could be returned in place of the real key when that key was absent, not
  visible, or listed after it.
- A finder that returns a single key (`FindKey`, `FindKeyWithAttributes`, `FindKeyPair`,
  `FindKeyPairWithAttributes`, `FindPrivateKey`, `FindPrivateKeyWithAttributes`,
  `FindRSAPrivateKey`, `FindRSAKeyPair`, `FindMLKEMKeyPair`) now reports an error when more
  than one key matches, instead of returning whichever the token listed first.
- A session the pool opens is now checked before it is handed out: the slot must still hold the
  token the Context was configured for, and the session must be logged in. When the login went
  away underneath the Context (a `C_Logout` elsewhere in the process, an HSM-side timeout, a
  reconnect), operations went on in sessions that were no longer logged in, and after a token
  was swapped they ran on the new token. They now fail with an error saying the login is lost
  or the token changed. crypto11 does not keep the PIN, so it does not log in again: close the
  Context and configure a new one. `CKR_USER_NOT_LOGGED_IN` now retires the session it came
  from, so the next operation runs that check.
- `SecretKey.NewHMAC` no longer takes a pooled session, with the Context's read lock, the
  moment it is called. It held both until `Sum`, and an HMAC that was dropped before `Sum`, as
  when a caller rejects a message before computing its MAC, never gave them back: the pool
  drained one session at a time, and `Close` waited forever. The session is now taken by the
  first `Write` or `Sum` and given back by `Sum`, and an HMAC dropped in between gives it back
  when the garbage collector finalizes it.
- An HMAC from `NewHMAC` now fails closed when data is written after `Sum`. The token has
  ended the operation by then, so the data cannot be added; `Write` returned an error, but a
  caller that ignored it got the MAC of the earlier data alone from the next `Sum`. That
  `Write` now leaves the hash dead until `Reset`, and `Sum` panics.
- The verify-after-sign check on RSA signatures now also covers keys found without their public
  half, through `FindPrivateKey`, `FindRSAPrivateKey` and their variants. Those keys carried no
  public key, so their signatures were returned unchecked, and a signature from a faulty CRT
  computation reveals the private key. The public key is now read from the private key object
  itself (`CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`, or `CKA_PUBLIC_KEY_INFO`). Only a key whose
  token exposes none of these is still not checked.
- A pooled session is now retired when a token operation fails with an error that did not come
  from the token. When pkcs11-go gives up on a call, for instance because the output would
  exceed its 64 MiB limit, the token is never told and the operation stays active; the session
  went back to the pool, and the next caller to draw it failed with `CKR_OPERATION_ACTIVE`, or
  lost the session objects on it when that error retired it. An oversize AES-GCM `Seal` or
  `Open`, or CBC `CryptBlocks`, was enough.
- ML-KEM `Decapsulate` now refuses a ciphertext whose length is not the one FIPS 203 fixes for
  the key's parameter set (768, 1088 or 1568 bytes) before it reaches the token. Some modules,
  SoftHSMv2 among them, answer a wrong length with `CKR_GENERAL_ERROR`, which retired the pooled
  session and destroyed the session objects other callers had on it. `Encapsulate` checks the
  length the token returns the same way when the parameter set is known.
- Keys and certificates created as session objects (`CKA_TOKEN = false`) are now created on the
  Context's persistent session, which lasts as long as the Context, one caller at a time. A
  session object lives only as long as the session that created it, and it was created on a
  pooled session, which is closed whenever an error retires it, possibly on another caller's
  operation; the object then vanished. ML-KEM shared secrets, which callers keep only for one
  operation, are still created on pooled sessions.
- `Configure` no longer accepts any PIN for a token that another Context in the process has
  already logged in. Login state belongs to the application, so `C_Login` answers
  `CKR_USER_ALREADY_LOGGED_IN` without checking the PIN, and crypto11 took that as success: a
  Context with a wrong PIN got the first one's access. crypto11 now keeps a keyed digest (an
  HMAC under a per-process random key) of the PIN it logged each token in with, and refuses a
  later Context that presents a different one. A login made outside crypto11 is still accepted
  as before, since there is nothing to compare with.
- `Configure` now fails when the configured token label or serial number matches more than one
  token, instead of using whichever slot is listed first. Labels are chosen by whoever
  initialises a token, so another token initialised with the same label in a lower slot was
  silently used in place of the intended one.
- `Close` no longer deadlocks with an operation started while it waits. Operations held a
  read lock that `Close` took for writing, and a waiting writer blocks new readers, so a request
  that held a session (an open CBC block mode, say) and then started another operation waited
  on `Close`, which waited on it. Once `Close` has begun, new operations now fail at once with
  "context is closed", and `Close` also wakes operations waiting for a pooled session. The
  `PoolWaitTimeout` documentation now warns that a caller holding one session while waiting for
  another can wait for ever with the default of zero.
- `Configure` now refuses a relative `Config.Path`. It used to resolve one against the working
  directory, which defeated pkcs11-go's own refusal: a library planted in the working directory
  under that name would be loaded, and its code run, in the process.
- `ConfigureFromFile` now refuses a config file owned by anyone but the current user or root
  (not checked on Windows). The mode checks said nothing about a file someone else owns, who can
  change its mode and rewrite it, and the file names the library `Configure` loads.
- ECDSA and Ed25519 signatures are now verified against the public key before they are
  returned, as RSA signatures already were, since a signature computed with a fault can reveal
  the private key; for deterministic Ed25519, two signatures of one message are enough. A key
  found without its public half is checked against the `CKA_PUBLIC_KEY_INFO` of its private key
  object when the token sets it.
- AES-GCM `Seal` now refuses output that is not exactly the plaintext plus the tag, and `Open`
  plaintext that is not exactly the ciphertext less the tag (or, where the token appends its own
  IV, longer than the ciphertext); a ciphertext shorter than the tag is refused without asking
  the token. A short `Seal` result would have handed the caller a truncated tag.
- `MLKEMDeriveKey` now refuses a shared secret that is not the 32 bytes FIPS 203 defines. It
  accepted any length, and an empty secret, from a token that did not return the value for
  instance, derived a fixed key anyone could compute.

### Changed

- `Config.Path` must be absolute.
- The finders no longer return a secret or private key with `CKA_PRIVATE = false` on a Context
  that logs in. Keys crypto11 generates are private by default. To find one that is not, pass
  `CKA_PRIVATE = false` in the attribute set of a `WithAttributes` finder.
- `NewHMAC` no longer reports a failure to start the signing operation on the token, such as
  a key that may not sign; the first `Write` returns it (or `Sum` panics with it). `Reset` no
  longer takes a session, so it cannot fail.
- Build and test toolchain bumped from `go1.27.3` to `go1.27.4` (`toolchain` directive in
  `go.mod`, `.go-version`, and the version noted in `CONTRIBUTING.md`). go1.27.4 fixes
  `GO-2026-6859` in `net/http`, which `govulncheck` flagged on go1.27.3.
- `github.com/eclipse-keypont/pkcs11-go` bumped from `v1.2.0` to `v1.3.0`, which carries the
  round-2 fixes this release relies on: an operation the binding gives up on is ended with
  `C_SessionCancel`, module-reported counts and lengths are bounded, and a NULL function-list
  entry answers `CKR_FUNCTION_NOT_SUPPORTED`. Exported additions there (`ErrOutputTooLarge`,
  `ErrOperationActive`) let a caller tell those failure modes apart.

## v2.0.0 — pkcs11-go, PKCS#11 v3.2 and ML-KEM

v2 is a breaking release (hence the `/v2` module path) driven by three changes: the PKCS#11 binding
was replaced, the config file was renamed, and the API surface was hardened after a security audit.

### Breaking changes

- `MLKEMDecapsulator` now requires `Encapsulator() Encapsulator`, which exposes the matching
  public key for encapsulation. External implementations and mocks of `MLKEMDecapsulator`
  (including those implementing `MLKEMKeyPair`) must add this method.
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
  (`mlkem.go`). `MLKEMKeyPair.Encapsulator()` exposes the matching public key through the new
  `Encapsulator` interface (`crypto11.go`).
- `MLKEMDeriveKey`, a KMAC-based key derivation helper for turning ML-KEM shared secrets into
  usable keys.
- **Ed25519** key generation and signing (`GenerateEd25519KeyPair`, `…WithLabel`,
  `…WithAttributes`), over PKCS#11 v3.0's `CKM_EC_EDWARDS_KEY_PAIR_GEN` and `CKM_EDDSA`
  (`ed25519.go`). Keys are returned as `Signer`, found again by the `FindKeyPair` and
  `FindPrivateKey` families, and their public half as `crypto/ed25519.PublicKey`, so they drop
  into `x509.CreateCertificate` and `ed25519.Verify` unchanged. Only pure Ed25519 is signed:
  Ed25519ph and Ed25519ctx need `CK_EDDSA_PARAMS`, which the binding does not yet marshal, and
  `Sign` refuses them rather than silently signing the pure variant. An empty message is signed
  like any other: pkcs11-go now passes zero-length input as a valid buffer, where it used to pass
  a NULL pointer that SoftHSM2 rejects. `CKA_EC_POINT` is accepted
  both DER-wrapped and bare, `CKA_EC_PARAMS` as the OID or the `"edwards25519"` string. An
  Ed448 key — same `CKK_EC_EDWARDS` key type, no Go type to return it as — is skipped by
  enumeration rather than failing it, and a template asking for one is refused before any
  object is created. Both key-pair and private-key lookup check the private key's curve,
  including when a public object or certificate with the same ID belongs to another curve.
- `Config.PinFunc`, a callback that supplies the PIN as bytes to `Configure`, which wipes them as
  soon as the token has been logged into. For callers who would rather never hold the PIN in a
  Go `string`, which cannot be wiped.
- `Context.PoolStats`, returning session pool counters — capacity, available, active, in use,
  wait count and wait time — for metrics and diagnostics
  ([#119](https://github.com/eclipse-keypont/crypto11/issues/119), requested by
  [@eriklupander](https://github.com/eriklupander)). It reads in-memory counters only: no PKCS#11
  call, no session taken, safe to call concurrently or on a closed `Context`. The returned
  `PoolStats` is a plain struct, so the vendored `internal/pool` types stay out of the public API.
- `Config.ReadOnlySessions`, which opens every session — the persistent one and the pooled ones —
  without `CKF_RW_SESSION`, for tokens that refuse a read/write session outright (some answer
  `C_OpenSession` with `CKR_TOKEN_WRITE_PROTECTED`) and for deployments that only ever use keys
  provisioned elsewhere ([#109](https://github.com/eclipse-keypont/crypto11/pull/109), contributed
  by [@thuandb](https://github.com/thuandb)). A read-only session cannot create or destroy objects,
  so key generation, key import and object deletion fail with `CKR_SESSION_READ_ONLY` while it is
  set; signing, verification, encryption and decryption with existing keys are unaffected.
- **Demand-driven session allocation**: the pool now hands out a session that is already open in
  preference to opening a new one, so the number of sessions open on the token tracks the
  concurrency actually in flight rather than the number of operations served
  ([#142](https://github.com/eclipse-keypont/crypto11/issues/142), reported by
  [@robinsandhu](https://github.com/robinsandhu)). `PoolStats` gains an `IdleReused` counter. The
  session-recovery half of the same issue — a session the token has declared dead is closed and
  replaced rather than returned to the pool — landed earlier in
  [#144](https://github.com/eclipse-keypont/crypto11/pull/144).
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

- **`Delete` on a key pair without a public key object.** `FindKeyPair` takes the public half
  from a certificate when the token holds no public key object. `Delete` on such a pair destroyed
  the private key and then returned `CKR_OBJECT_HANDLE_INVALID` for the public object that does
  not exist, so a successful deletion was reported as a failure. It now returns nil and leaves
  the certificate, a separate object, for `DeleteCertificate`.
- **RSA-PSS options are checked before reaching the token.** A negative `PSSOptions.SaltLength`
  other than the two sentinels made `Sign` panic, since pkcs11-go's `NewPSSParams` panics on a
  negative salt. It is now an error wrapping `errUnsupportedRSAOptions`, as crypto/rsa makes it.
  An explicit salt longer than the modulus can carry is `rsa.ErrMessageTooLong`, again as in
  crypto/rsa, and a digest whose length is not the hash's size is an error rather than something
  left to the token, matching the PKCS#1 v1.5 path.
- **HMAC.** `NewHMAC` reported a `BlockSize` of 64 for `CKM_SHA384_HMAC` and
  `CKM_SHA384_HMAC_GENERAL`; SHA-384's block size is 128. For a `_GENERAL` mechanism it accepted
  any output length: 0 made every `Sum` panic on the empty MAC, and a negative length reached the
  token as a huge `CK_ULONG`. Lengths outside 1 to the hash's full size are now rejected with
  `errInvalidMACLength`. The size table is tested against Go's own hash implementations.
- **CBC `CryptBlocks` on empty input** is a no-op, as it is for crypto/cipher's block modes. It
  used to pass the empty slice to the token, and on SoftHSM2 panicked with
  `CKR_ARGUMENTS_BAD`.
- **Empty inputs.** AES-GCM `Seal` with an empty plaintext, which authenticates associated data
  only and is a legitimate use, panicked with `CKR_ARGUMENTS_BAD` on SoftHSM2. Ed25519 refused to
  sign an empty message. Both came from pkcs11-go passing zero-length input to the module as a
  NULL pointer; with the pkcs11-go release that passes a valid buffer, both work.
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

- Build and test toolchain bumped from `go1.27.2` to `go1.27.3` (`toolchain` directive in
  `go.mod`, `.go-version`, and the version noted in `CONTRIBUTING.md`). go1.27.3 is a patch
  release that fixes the `crypto/x509` standard-library vulnerability `GO-2026-6809`
  ("distrust compromised intermediate certificates") flagged by `govulncheck` on go1.27.2.
- **HMAC key generation tries the PKCS#11 v3.0 mechanisms first.** `CipherHMACSHA1` …
  `CipherHMACSHA512` now list `CKM_SHA_1_KEY_GEN` … `CKM_SHA512_KEY_GEN`, which v3.0
  standardised for `CKK_SHA*_HMAC` keys, ahead of the nShield vendor mechanisms and the
  `CKM_GENERIC_SECRET_KEY_GEN` fallback. Key generation also skips a (key type, mechanism) pair
  the token reports as `CKR_MECHANISM_INVALID` from `C_GetMechanismInfo`, instead of calling
  `C_GenerateKey` with it. A vendor-defined mechanism number now reaches only a token that
  reports supporting it, rather than every token, where the same number can mean something
  else. The last pair is always tried, so the error a caller sees is still the token's own.
- **crypto11 no longer contains any cgo of its own.** The `CK_ULONG` conversions were the last
  `import "C"` in the package; they now delegate to `cryptoki.ULongToBytes` / `cryptoki.BytesToULong`,
  added in pkcs11-go v1.1.0. This release requires v1.2.0, which carries the binding's own
  fixes for the Synapse security findings
  ([eclipse-keypont/pkcs11-go#15](https://github.com/eclipse-keypont/pkcs11-go/pull/15)) and the
  consolidated security review of the `cryptoki` and `p11` packages (memory-safety, input-validation
  and build-hardening fixes, plus a mechanism policy and secure-by-default key templates). The
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
  `NOTICE.md` generated from the dependency graph.
- `go.mod` follows the two-directive policy adopted on `master` in
  [#137](https://github.com/eclipse-keypont/crypto11/issues/137): `go 1.25.0` is the minimum a
  consumer needs — lowered from `go 1.26.1` in v1.7.0-rc1, since a library's `go` directive is a
  floor imposed on every importer — and `toolchain go1.27.2` is what maintainers build and test
  with. `.go-version` tracks the toolchain.
- Build and test toolchain bumped from `go1.27.1` to `go1.27.2` (`toolchain` directive in
  `go.mod`, `.go-version`, and the version noted in `CONTRIBUTING.md`). go1.27.2 is a patch
  release that fixes the `net/http` and `net/http/internal/http2` standard-library
  vulnerabilities flagged by `govulncheck` on go1.27.1.
- **`gosec` pinned to a `master` commit** (`7157726`, `x/tools` v0.52.0) in
  `.github/workflows/gosec.yml` and the `Makefile`, instead of the v2.29.0 release. The
  v2.29.0 release links `golang.org/x/tools` v0.49.0, which cannot decode the go1.27.2
  export data (version 5 is greater than the maximum supported version 4) and fails the
  scan with an import error. Move back to a tagged release once one ships
  `x/tools` >= v0.50.0.

### Deprecated

- **The `Cka*` attribute constants.** They were a hand-copied list of `CKA_*` values that had
  fallen behind the specification: 111 of the 160 attributes in the PKCS#11 v3.2 header, missing
  `CKA_UNIQUE_ID`, `CKA_PROFILE_ID`, `CKA_SEED`, `CKA_PUBLIC_CRC64_VALUE` and the validation and
  trust attributes. The pkcs11-go binding's `cryptoki` package is generated from that header
  and defines all of them, so each `Cka*` constant is now defined from the binding's constant of
  the same name, keeping its `AttributeType` type (`CkaLabel = AttributeType(pkcs11.CKA_LABEL)`),
  and marked deprecated. Existing code compiles and behaves as before; new code should use
  `pkcs11.CKA_*` directly, which `AttributeSet.Set` and every other `AttributeType` parameter
  already accept. crypto11 itself now uses the binding's
  constants throughout. `AttributeSet.String` names attributes with the binding's generated
  `cryptoki.AttributeName` (`CKA_VALUE`, not `CkaValue`), which also covers every attribute
  the old 180-line name table did not, instead of printing `Unknown` for them.

### CI/CD & supply chain

- Unified security/quality pipeline shared across the pkcs11-go / crypto11 / gose projects:
  CodeQL, govulncheck, native GitHub secret scanning, OpenSSF Scorecard, dependency review, and
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
