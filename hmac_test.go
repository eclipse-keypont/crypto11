// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"runtime"
	"sync"
	"testing"
	"time"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/crypto11/v2/internal/pool"
)

func TestHmac(t *testing.T) {
	ctx := testContext(t)

	// The hash-independent subtests (Empty/MultiSum/Reset) run once, under the plain
	// SHA256 case, so they exercise a mechanism that (virtually) every HSM supports. The
	// _GENERAL cases self-skip via skipIfMechUnsupported, as SoftHSM has no _GENERAL
	// variants.
	t.Run("HMACSHA1", func(t *testing.T) {
		testHmac(t, ctx, "hmac1", pkcs11.CKK_SHA_1_HMAC, pkcs11.CKM_SHA_1_HMAC, 0, 20, false)
	})
	t.Run("HMACSHA1General", func(t *testing.T) {
		testHmac(t, ctx, "hmac1", pkcs11.CKK_SHA_1_HMAC, pkcs11.CKM_SHA_1_HMAC_GENERAL, 10, 10, false)
	})
	t.Run("HMACSHA256", func(t *testing.T) {
		testHmac(t, ctx, "hmac0", pkcs11.CKK_SHA256_HMAC, pkcs11.CKM_SHA256_HMAC, 0, 32, true)
	})

}

// After a multi-part HMAC fails mid-operation, fail() releases the session and marks
// the hash dead. These tests cover the resulting dead-operation guards without an HSM.
func TestHmacWriteAfterSessionReleased(t *testing.T) {
	hi := &hmacImplementation{dead: true}
	n, err := hi.Write([]byte("data"))
	require.Equal(t, errHmacClosed, err)
	require.Zero(t, n)
}

func TestHmacSumAfterSessionReleased(t *testing.T) {
	hi := &hmacImplementation{dead: true}
	require.PanicsWithValue(t, errHmacClosed, func() {
		hi.Sum(nil)
	})
}

// TestGenerateHMACKeyFallback exercises the symmetric.go vendor-error fallback on a real
// token. Every exported CipherHMACSHA* leads with an nShield vendor key-gen mechanism
// (CKM_NC_*). A token that lacks it — SoftHSMv3 (pqctoday-hsm,
// https://github.com/pqctoday-org/pqctoday-hsm) returns CKR_MECHANISM_INVALID, Utimaco
// CKR_ATTRIBUTE_TYPE_INVALID — must fall through to the generic-secret GenParam. Before
// the fallback was broadened, GenerateSecretKey failed outright on those tokens; here we
// prove each key generates and then produces a working HMAC.
func TestGenerateHMACKeyFallback(t *testing.T) {
	ctx := testContext(t)

	// keyBits is the key length to generate, in bits. It is the digest size of
	// the matching hash, which is the natural HMAC key size and — importantly —
	// never below the mechanism's minimum: PKCS#11 requires a SHA384-HMAC key of
	// at least 48 bytes and a SHA512-HMAC key of at least 64 bytes, so a fixed
	// 256-bit key is rejected with CKR_KEY_SIZE_RANGE by a spec-conformant token
	// (SoftHSMv2 >= 2.7.0). The apt 2.6.1 package advertised a bogus minimum of
	// one byte, which is why the undersized key used to slip through.
	cases := []struct {
		name    string
		cipher  *SymmetricCipher
		mech    uint
		size    int
		keyBits int
	}{
		{"SHA1", CipherHMACSHA1, pkcs11.CKM_SHA_1_HMAC, 20, 160},
		{"SHA224", CipherHMACSHA224, pkcs11.CKM_SHA224_HMAC, 28, 224},
		{"SHA256", CipherHMACSHA256, pkcs11.CKM_SHA256_HMAC, 32, 256},
		{"SHA384", CipherHMACSHA384, pkcs11.CKM_SHA384_HMAC, 48, 384},
		{"SHA512", CipherHMACSHA512, pkcs11.CKM_SHA512_HMAC, 64, 512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The generation itself is the assertion for the fallback fix: on a token
			// without the vendor mech this only succeeds because of the generic-secret
			// fall-through.
			key, err := ctx.GenerateSecretKey(randomBytes(), tc.keyBits, tc.cipher)
			require.NoError(t, err)
			require.NotNil(t, key)
			defer func() { _ = key.Delete() }()

			// Where the matching HMAC mechanism exists, prove the generated key is usable.
			skipIfMechUnsupported(t, ctx, tc.mech)
			h, err := key.NewHMAC(int(tc.mech), 0)
			require.NoError(t, err)
			n, err := h.Write([]byte("the quick brown fox"))
			require.NoError(t, err)
			require.Equal(t, len("the quick brown fox"), n)
			require.Len(t, h.Sum(nil), tc.size)
		})
	}
}

// TestHmacConcurrent stresses the session get/put/cleanup cycle that PR #135 hardened. A
// double pool.Put would hand one session to two goroutines, so interleaved SignInit/
// SignUpdate would corrupt results or error; every goroutine must reproduce the same
// reference MAC. It runs many more HMAC operations than the pool holds, forcing reuse.
// Verified against SoftHSMv3 (pqctoday-hsm, https://github.com/pqctoday-org/pqctoday-hsm).
func TestHmacConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ctx := testContext(t)

	skipIfMechUnsupported(t, ctx, pkcs11.CKM_SHA256_HMAC)

	key, err := ctx.GenerateSecretKey(randomBytes(), 256, CipherHMACSHA256)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	errMismatch := errors.New("hmac mismatch")
	input := []byte("concurrent hmac integrity check")

	// Single-threaded reference.
	ref, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	require.NoError(t, err)
	_, err = ref.Write(input)
	require.NoError(t, err)
	want := ref.Sum(nil)

	const workers, perWorker = 16, 64
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				h, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
				if err != nil {
					errs <- err
					return
				}
				if _, err = h.Write(input); err != nil {
					errs <- err
					return
				}
				if got := h.Sum(nil); !bytes.Equal(want, got) {
					errs <- errMismatch // mismatch signals session corruption
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
}

func testHmac(t *testing.T, ctx *Context, keyLabel string, keytype int, mech int, length int, xlength int, full bool) {

	skipIfMechUnsupported(t, ctx, uint(mech))

	key, found, err := findKeyOrCreate(ctx, keyLabel, keytype, 256)
	require.NoError(t, err)
	require.NotNil(t, key)
	if !found {
		// so it was created
		defer key.Delete()
	}

	t.Run("Short", func(t *testing.T) {
		input := []byte("a short string")
		h1, err := key.NewHMAC(mech, length)
		require.NoError(t, err)

		n, err := h1.Write(input)
		require.NoError(t, err)
		require.Equal(t, len(input), n)

		r1 := h1.Sum([]byte{})
		h2, err := key.NewHMAC(mech, length)
		require.NoError(t, err)

		n, err = h2.Write(input)
		require.NoError(t, err)
		require.Equal(t, len(input), n)

		r2 := h2.Sum([]byte{})

		require.Equal(t, r1, r2)
		require.Len(t, r1, xlength)
	})
	if full { // Independent of hash, only do these once
		t.Run("Empty", func(t *testing.T) {
			// Must be able to MAC empty inputs without panicing
			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)
			h1.Sum([]byte{})
		})
		t.Run("MultiSum", func(t *testing.T) {
			input := []byte("a different short string")

			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)

			n, err := h1.Write(input)
			require.NoError(t, err)
			require.Equal(t, len(input), n)

			r1 := h1.Sum([]byte{})
			r2 := h1.Sum([]byte{})
			require.Equal(t, r1, r2)

			// Can't add more after Sum()
			_, err = h1.Write(input)
			require.Equal(t, errHmacClosed, err)

			// 0-length is special
			n, err = h1.Write([]byte{})
			require.NoError(t, err)
			require.Zero(t, n)
		})
		t.Run("Reset", func(t *testing.T) {

			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)

			n, err := h1.Write([]byte{1})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			r1 := h1.Sum([]byte{})
			h1.Reset()

			n, err = h1.Write([]byte{2})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			r2 := h1.Sum([]byte{})
			h1.Reset()

			n, err = h1.Write([]byte{1})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			r3 := h1.Sum([]byte{})
			require.Equal(t, r1, r3)
			require.NotEqual(t, r1, r2)
		})
		t.Run("ResetFast", func(t *testing.T) {
			// Reset() immediately after creation should be safe

			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)
			h1.Reset()
			n, err := h1.Write([]byte{2})
			require.NoError(t, err)
			require.Equal(t, 1, n)
			h1.Sum([]byte{})
		})
	}
}

func TestCheckMACLength(t *testing.T) {
	require.NoError(t, checkMACLength(make([]byte, 32), 32))
	require.Error(t, checkMACLength(nil, 32), "empty MAC")
	require.Error(t, checkMACLength(make([]byte, 31), 32), "truncated MAC")
	require.Error(t, checkMACLength(make([]byte, 33), 32), "oversized MAC")
	// Unknown mechanism, no length given: only emptiness can be checked.
	require.NoError(t, checkMACLength(make([]byte, 7), 0))
	require.Error(t, checkMACLength(nil, 0))
}

func TestHmacInfoSizesMatchDigests(t *testing.T) {
	// The table is what Sum validates token output against, so a wrong size
	// (MD5 was listed at 20 bytes) rejects every correct MAC; and its block size
	// is what BlockSize reports (SHA-384 was listed at 64 bytes, not 128). Both
	// are checked against Go's own implementation of each hash.
	hashes := map[int]func() hash.Hash{
		pkcs11.CKM_MD5_HMAC:        md5.New,
		pkcs11.CKM_SHA_1_HMAC:      sha1.New,
		pkcs11.CKM_SHA224_HMAC:     sha256.New224,
		pkcs11.CKM_SHA256_HMAC:     sha256.New,
		pkcs11.CKM_SHA384_HMAC:     sha512.New384,
		pkcs11.CKM_SHA512_HMAC:     sha512.New,
		pkcs11.CKM_SHA512_224_HMAC: sha512.New512_224,
		pkcs11.CKM_SHA512_256_HMAC: sha512.New512_256,
	}
	// Each _GENERAL mechanism is its plain one plus one.
	for mech, newHash := range hashes {
		h := newHash()
		for _, m := range []int{mech, mech + 1} {
			info, ok := hmacInfos[m]
			require.True(t, ok, "mechanism %#x missing from hmacInfos", m)
			assert.Equal(t, h.Size(), info.size, "size of %#x", m)
			assert.Equal(t, h.BlockSize(), info.blockSize, "block size of %#x", m)
			assert.Equal(t, m == mech+1, info.general, "general flag of %#x", m)
		}
	}
	// RIPEMD-160 has no implementation in the standard library.
	assert.Equal(t, 20, hmacInfos[pkcs11.CKM_RIPEMD160_HMAC].size)
	assert.Equal(t, 64, hmacInfos[pkcs11.CKM_RIPEMD160_HMAC].blockSize)
}

func TestNewHMACRejectsInvalidLength(t *testing.T) {
	// The length is checked before a session is taken, so no token is needed.
	key := &SecretKey{}
	for _, c := range []struct {
		mech, length int
	}{
		{pkcs11.CKM_SHA256_HMAC_GENERAL, 0},
		{pkcs11.CKM_SHA256_HMAC_GENERAL, -1},
		{pkcs11.CKM_SHA256_HMAC_GENERAL, 33},
		{pkcs11.CKM_SHA_1_HMAC_GENERAL, 21},
		{pkcs11.CKM_VENDOR_DEFINED, -1}, // not in the table
	} {
		_, err := key.NewHMAC(c.mech, c.length)
		require.ErrorIs(t, err, errInvalidMACLength, "mechanism %#x, length %d", c.mech, c.length)
	}
}

func TestHmacResetAfterDeadOperationDoesNotPanic(t *testing.T) {
	// Reset used to call Sum unconditionally; on a hash whose operation had
	// already died that panicked instead of trying to start over.
	closed := pool.NewResourcePool(func() (pool.Resource, error) { return nil, errors.New("unused") }, 1, 1, 0, 0)
	closed.Close()
	ctx := &Context{cfg: &Config{}, pool: closed}
	hi := &hmacImplementation{key: &SecretKey{pkcs11Object: pkcs11Object{context: ctx}}, dead: true}
	// Reset takes no session, so it cannot fail; the next Write tries to start
	// an operation, fails on the closed pool, and leaves the hash dead.
	require.NotPanics(t, func() { hi.Reset() })
	_, err := hi.Write([]byte("x"))
	require.Error(t, err)
	_, err = hi.Write([]byte("x"))
	require.Equal(t, errHmacClosed, err)
	require.Panics(t, func() { hi.Sum(nil) })
}

func TestHmacResetFailureDoesNotReplayPreviousMAC(t *testing.T) {
	// A pool of exactly one session, with a short wait, lets the test make the
	// reinitialization inside Reset fail deterministically by holding that one
	// session elsewhere.
	cfg := testConfig(t)
	cfg.MaxSessions = 2
	cfg.PoolWaitTimeout = 200 * time.Millisecond
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()

	skipIfMechUnsupported(t, ctx, pkcs11.CKM_SHA256_HMAC)
	key, found, err := findKeyOrCreate(ctx, "hmac0", pkcs11.CKK_SHA256_HMAC, 256)
	require.NoError(t, err)
	if !found {
		defer key.Delete()
	}

	h, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	require.NoError(t, err)
	_, err = h.Write([]byte("first message"))
	require.NoError(t, err)
	first := h.Sum(nil)
	require.Len(t, first, 32)

	// Starve the pool, then Reset and Write: the new operation cannot get a
	// session.
	held, err := ctx.getSession()
	require.NoError(t, err)
	h.Reset()
	_, err = h.Write([]byte("second message"))
	require.Error(t, err)
	ctx.putSession(held, nil)

	// The hash is dead. It must say so — not hand back the MAC of "first
	// message" as if it were the MAC of whatever comes next.
	_, err = h.Write([]byte("second message"))
	require.Equal(t, errHmacClosed, err)
	require.Panics(t, func() { h.Sum(nil) })
}

// TestHMACTakesNoSessionUntilWritten checks that NewHMAC and Reset take no
// session from the pool: an HMAC that is created and never used, as when a
// caller gives up before using it, costs nothing.
func TestHMACTakesNoSessionUntilWritten(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSessions = 2 // a single pooled session
	cfg.PoolWaitTimeout = 200 * time.Millisecond
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_SHA256_HMAC)
	key, found, err := findKeyOrCreate(ctx, "hmac0", pkcs11.CKK_SHA256_HMAC, 256)
	require.NoError(t, err)
	if !found {
		defer key.Delete()
	}

	// More unused HMACs than the pool has sessions: each would otherwise strand one.
	for range 3 {
		_, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
		require.NoError(t, err)
		require.Zero(t, ctx.PoolStats().InUse, "an unused HMAC holds a session")
	}
	h, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	require.NoError(t, err)
	h.Reset()
	require.Zero(t, ctx.PoolStats().InUse, "Reset takes a session")

	h, err = key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	require.NoError(t, err)
	_, err = h.Write([]byte("message"))
	require.NoError(t, err)
	require.Len(t, h.Sum(nil), 32)
	require.Zero(t, ctx.PoolStats().InUse, "Sum gives the session back")
}

// TestAbandonedHMACReleasesSession checks that an HMAC dropped between Write
// and Sum gives its session back when it is finalized, and that the pool can
// hand out a working session again.
func TestAbandonedHMACReleasesSession(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSessions = 2 // a single pooled session
	cfg.PoolWaitTimeout = 200 * time.Millisecond
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_SHA256_HMAC)
	key, found, err := findKeyOrCreate(ctx, "hmac0", pkcs11.CKK_SHA256_HMAC, 256)
	require.NoError(t, err)
	if !found {
		defer key.Delete()
	}

	func() {
		h, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
		require.NoError(t, err)
		_, err = h.Write([]byte("abandoned"))
		require.NoError(t, err)
		require.Equal(t, int64(1), ctx.PoolStats().InUse)
	}()

	require.Eventually(t, func() bool {
		runtime.GC()
		return ctx.PoolStats().InUse == 0
	}, 5*time.Second, 50*time.Millisecond, "the abandoned HMAC never gave its session back")

	h, err := key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	require.NoError(t, err)
	_, err = h.Write([]byte("message"))
	require.NoError(t, err)
	require.Len(t, h.Sum(nil), 32)
}
