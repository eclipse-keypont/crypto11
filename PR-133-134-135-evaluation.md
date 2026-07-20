# Evaluation — PRs #133, #134, #135 → `pkcs11-v3.2-ml-kem`

This is the evaluation of [PR #133](https://github.com/ThalesGroup/crypto11/pull/133), [PR #134](https://github.com/ThalesGroup/crypto11/pull/134), and [PR #135](https://github.com/ThalesGroup/crypto11/pull/135) against the `pkcs11-v3.2-ml-kem` branch.

This is also a security analysis of the three PRs, not a mergeable patch.

Done with Anthropic Claude Opus 4.8.

## Summary

All three PRs target `master`, but the `pkcs11-v3.2-ml-kem` branch has diverged in one
way that affects **all** of them: commit `7d2c154` replaced `github.com/miekg/pkcs11`
with `github.com/eclipse-keypont/pkcs11-go/cryptoki`.

**All three PRs still import `github.com/miekg/pkcs11` directly**, so none will merge and
compile cleanly as-is — they must be ported to the eclipse-keypont binding first. The
alias (`pkcs11`) and API surface are largely the same (it is a fork), so this is
mechanical work, not a redesign — but it is a hard prerequisite, not optional.

---

## PR #133 — Unified EC keygen (ECDSA + ECDH) · +661/−4 · author `Armageddon6026`

Adds `ec.go`: unified `GenerateECKeyPair*` APIs, a `Deriver` interface, ECDH1 derive,
and custom-KDF key-size registration. Deprecates the old ECDSA-only generators.

**Security assessment — moderate, mostly acceptable:**

- ✅ Derived keys and generated private keys default to `CKA_SENSITIVE=true`,
  `CKA_EXTRACTABLE=false` (keys stay in the HSM). The PR deliberately fixed the old
  PR #70 pattern of returning raw `byte[]` shared secrets (PCI-DSS concern); it now
  returns a `SecretKey` handle instead.
- ⚠️ **Raw ECDH with `CKD_NULL`**: `getECDH1KeySize` supports a null KDF, taking the raw
  ECDH X-coordinate as key material. Standard PKCS#11 but cryptographically a footgun
  (no KDF, biased top bytes). Caller-driven, so acceptable — worth a doc warning.
- ⚠️ **Test reads secret material**: `ec_test.go` sets `CKA_EXTRACTABLE=true` /
  `CKA_SENSITIVE=false` to compare shared secrets. Fine for tests; must not be copied
  into production examples.

**Mergeability — most disruptive of the three:**

- Renames the EC key concept (`pkcs11PrivateKeyECDSA` → `pkcs11PrivateKeyEC`,
  `CKK_ECDSA` case → `CKK_EC`). Written against master's `keys.go` (one reference site);
  the branch has **four** (`keys.go:205,531,693,738`) plus `ecdsa.go`. A merge leaves
  dangling references and **will not compile** without manual reconciliation.
- **Collides with PR #134**, which still expects `pkcs11PrivateKeyECDSA`.

---

## PR #134 — Import existing ECDSA private keys · +204/−0 · author `is-alnilam`

Adds `ImportECDSAKeyPair*` to load an externally-generated `*ecdsa.PrivateKey` onto the
token via `CreateObject` (sets `CKA_VALUE` = private scalar). Clean rollback of the
orphaned public key on failure.

**Security assessment — the one to scrutinize:**

- 🔴 **Insecure default for imported private keys.** The import path calls
  `AddIfNotPresent` with only `CKA_TOKEN` and `CKA_SIGN` — it does **not** set
  `CKA_SENSITIVE=true` / `CKA_EXTRACTABLE=false`. The generate path (ecdsa.go:245-250)
  sets both. So an imported private key defaults to whatever the token allows —
  potentially **extractable and non-sensitive**. Recommend hardening before merge:
  default sensitive=true, extractable=false; let callers opt out.
- ⚠️ **Inherent trust-boundary change (by design).** Importing means the private key was
  generated *outside* the HSM and lives in Go process memory (`value := ecdhKey.Bytes()`),
  never zeroized. This defeats the "keys never leave the HSM" guarantee. That is the
  point of the feature, but it is a policy decision for the ML-KEM threat model.
- ✅ Rollback logic correct; nil key rejected; P-224 correctly rejected (crypto/ecdh has
  no P-224).

**Mergeability:** Depends on `pkcs11PrivateKeyECDSA` — **directly conflicts with PR #133's
rename.** Pick one model. Plus the miekg → eclipse-keypont port.

---

## PR #135 — HMAC session-leak fix · +53/−11 · author `is-alnilam`

Fixes a **real resource leak**: on mid-operation HMAC errors the session was not returned
to the pool. Adds idempotent `cleanup` (nil-guard against double-return), fails
`Write` / panics `Sum` after a released session, and broadens the symmetric key-gen
vendor error fallback (`symmetric.go`).

**Security assessment — net positive, lowest risk:**

- ✅ Fixes a session/handle leak → prevents **pool exhaustion (DoS)** under HSM fault
  conditions (trigger was CloudHSM node removal). Genuine hardening fix.
- ✅ Double-cleanup guard is correct and prevents the more dangerous bug (same session
  handed to two callers). Reuses existing `errHmacClosed` (hmac.go:93).
- ⚠️ **`symmetric.go` fallback broadening** now also treats `CKR_MECHANISM_INVALID` and
  `CKR_ATTRIBUTE_TYPE_INVALID` as "fall through to generic-secret key." Low risk, but it
  means more conditions silently downgrade a vendor-specific HMAC key type to a generic
  secret. Confirm it cannot mask a genuinely misconfigured key request.
- ✅ Note the Go operator-precedence subtlety: the original `&&`/`||` mix was arguably
  buggy; the new version parenthesizes correctly.
- Test changes only remove the SoftHSM HMAC skip and move flags; no production impact.

**Mergeability:** Cleanest of the three. Touches `hmac.go` / `symmetric.go`, which the
branch also modified (security-audit commit `9593dd2` + the eclipse-keypont migration) —
expect small conflicts plus the miekg port, but no architectural collision.

---

## Recommendation

| PR                       | Contribution value         | Cyber risk                                            | Verdict for ML-KEM branch                                                                                                                                 |
|--------------------------|----------------------------|-------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **#135** HMAC leak fix   | High (fixes DoS-class bug) | Low / net positive                                    | **Take first.** Port to eclipse-keypont, review the `symmetric.go` fallback, merge.                                                                       |
| **#134** EC key import   | Medium (useful, niche)     | **Medium** — insecure default + trust-boundary change | **Conditional.** Only after fixing the sensitive/extractable default. Confirm importing off-HSM keys fits the threat model.                               |
| **#133** Unified EC/ECDH | Medium-High (real feature) | Moderate (raw-ECDH footgun)                           | **Highest effort / defer.** Biggest merge surface, type-rename conflicts with the 4 call sites *and* with #134. Reconcile the EC type model deliberately. |

**Suggested order of operations:**

1. **Merge #135 first** — port to `eclipse-keypont/pkcs11-go`, review the `symmetric.go`
   fallback, merge.
2. **Decide the EC key-type model once** — either #133's `pkcs11PrivateKeyEC` rename or
   the current `pkcs11PrivateKeyECDSA` model, not both independently.
3. **Harden #134's import defaults** (sensitive=true, extractable=false) and port.
4. **Port #133** last (largest surface).

**Two gating questions only the maintainer can answer (block #133/#134):**

1. Is **importing externally-generated private keys** (keys that exist outside the HSM)
   acceptable for the ML-KEM security posture?
2. Keep the **unified EC type rename** (#133) or the current `pkcs11PrivateKeyECDSA`
   model? This decides whether #133 and #134 can coexist.
