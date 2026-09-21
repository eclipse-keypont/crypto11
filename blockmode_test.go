// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/stretchr/testify/require"
)

func TestBlockMode(t *testing.T) {
	ctx := testContext(t)

	// get or generate a new temporary key for encryption / decryption operations in the pkcs11 store
	key, found, err := findKeyOrCreate(ctx, "aes0", pkcs11.CKK_AES, 256)
	if err != nil {
		panic(err)
	}
	if !found {
		// so it was dynamically created
		defer key.Delete()
	}

	iv, _ := makeIV(key.Cipher)

	t.Run("cbc mode", func(t *testing.T) { testCBCMode(t, key, iv) })
}

func trimSize(input []byte, blockSize int) (res []byte) {
	if len(input)%blockSize != 0 {
		multiplier := len(input) / blockSize
		res = make([]byte, (multiplier+1)*blockSize)
		copy(res, input)
		return
	}
	return input
}

func initBlock(character byte, length int) []byte {
	dst := make([]byte, length)
	for i := 0; i < length; i++ {
		dst[i] = character
	}
	return dst
}

func testCBCMode(t *testing.T, key *SecretKey, iv []byte) {
	a := []byte("ping")
	b := initBlock('v', 100)
	short := trimSize(a, len(iv))
	long := trimSize(b, len(iv))

	// ENCRYPTION
	// short
	bmeShort, err := key.NewCBCEncrypterCloser(iv)
	require.NoError(t, err)
	cShort := make([]byte, len(short))
	bmeShort.CryptBlocks(cShort, short)
	bmeShort.Close()
	require.Equal(t, 0, len(cShort)%len(iv))
	require.NotContains(t, string(cShort), string(short), "ciphertext does not contain plaintext")
	// long
	bmeLong, err := key.NewCBCEncrypterCloser(iv)
	require.NoError(t, err)
	cLong := make([]byte, len(long))
	bmeLong.CryptBlocks(cLong, long)
	bmeLong.Close()
	require.Equal(t, 0, len(cLong)%len(iv))
	require.NotContains(t, string(cLong), string(long), "ciphertext does not contain plaintext")

	// DECRYPTION
	// short
	bmdShort, err := key.NewCBCDecrypterCloser(iv)
	require.NoError(t, err)
	pShort := make([]byte, len(short))
	bmdShort.CryptBlocks(pShort, cShort)
	bmdShort.Close()
	require.Equal(t, 0, len(pShort)%len(iv))
	require.Contains(t, string(pShort), string(short), "plaintext contains original text")
	// long
	pLong := make([]byte, len(long))
	bmd2, err := key.NewCBCDecrypterCloser(iv)
	require.NoError(t, err)
	bmd2.CryptBlocks(pLong, cLong)
	bmd2.Close()
	require.Equal(t, 0, len(pLong)%len(iv))
	require.Contains(t, string(pLong), string(long), "plaintext contains original text")

}

func TestBlockModeFinalizerNeverPanics(t *testing.T) {
	// Build block modes on a session that was closed behind the pool's back,
	// so C_DecryptFinal fails with CKR_SESSION_HANDLE_INVALID — the kind of
	// token error the finalizer used to turn into an unrecoverable panic.
	cfg := testConfig(t)
	cfg.MaxSessions = 3
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()

	deadBlockMode := func() *blockModeCloser {
		s, err := ctx.getSession()
		require.NoError(t, err)
		require.NoError(t, s.ctx.CloseSession(s.handle))
		return &blockModeCloser{
			session:   s,
			blockSize: 16,
			mode:      modeDecrypt,
			// The dead session is not reusable; ask the pool for a fresh one.
			cleanup: func() { ctx.pool.Put(nil) },
		}
	}

	// From the runtime finalizer: the error is dropped, nothing panics.
	bmc := deadBlockMode()
	require.NotPanics(t, func() { finalizeBlockModeCloser(bmc) })
	require.Nil(t, bmc.session, "the session must have been released regardless")
	require.NotPanics(t, func() { finalizeBlockModeCloser(bmc) }, "and a second run is a no-op")

	// From an explicit Close the caller still gets the panic they always did.
	bmc = deadBlockMode()
	require.Panics(t, func() { bmc.Close() })
	require.Nil(t, bmc.session)

	// The pool recovered from both.
	_, err = ctx.FindKeys(randomBytes(), nil)
	require.NoError(t, err)
}
