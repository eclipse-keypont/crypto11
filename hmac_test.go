// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

func TestHmac(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

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

// After a multi-part HMAC fails mid-operation, cleanup() releases the session and nils
// it out. These tests cover the resulting dead-operation guards without an HSM: a
// zero-value hmacImplementation has both session and result nil, the same dead state.
func TestHmacWriteAfterSessionReleased(t *testing.T) {
	hi := &hmacImplementation{}
	n, err := hi.Write([]byte("data"))
	require.Equal(t, errHmacClosed, err)
	require.Zero(t, n)
}

func TestHmacSumAfterSessionReleased(t *testing.T) {
	hi := &hmacImplementation{}
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
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)
	defer func() { require.NoError(t, ctx.Close()) }()

	cases := []struct {
		name   string
		cipher *SymmetricCipher
		mech   uint
		size   int
	}{
		{"SHA1", CipherHMACSHA1, pkcs11.CKM_SHA_1_HMAC, 20},
		{"SHA224", CipherHMACSHA224, pkcs11.CKM_SHA224_HMAC, 28},
		{"SHA256", CipherHMACSHA256, pkcs11.CKM_SHA256_HMAC, 32},
		{"SHA384", CipherHMACSHA384, pkcs11.CKM_SHA384_HMAC, 48},
		{"SHA512", CipherHMACSHA512, pkcs11.CKM_SHA512_HMAC, 64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The generation itself is the assertion for the fallback fix: on a token
			// without the vendor mech this only succeeds because of the generic-secret
			// fall-through.
			key, err := ctx.GenerateSecretKey(randomBytes(), 256, tc.cipher)
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

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)
	defer func() { require.NoError(t, ctx.Close()) }()

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
