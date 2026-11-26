// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"errors"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gcmKey generates a session AES-128 key on a context configured by configure.
func gcmKey(t *testing.T, configure func(*Config)) *SecretKey {
	t.Helper()
	cfg := testConfig(t)
	configure(cfg)
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_AES_GCM)

	key, err := ctx.GenerateSecretKey(randomBytes(), 128, CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = key.Delete() })
	return key
}

// sealPanic returns what Seal panicked with, or nil.
func sealPanic(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, nonce []byte) (cause any) {
	defer func() { cause = recover() }()
	aead.Seal(nil, nonce, []byte("plaintext"), []byte("aad"))
	return nil
}

func TestGCMNonceLength(t *testing.T) {
	key := gcmKey(t, func(*Config) {})
	aead, err := key.NewGCM()
	require.NoError(t, err)
	require.Equal(t, DefaultGCMIVLength, aead.NonceSize())

	for _, n := range []int{0, 1, 12, aead.NonceSize() + 1} {
		assert.Equal(t, errGCMNonceLength, sealPanic(aead, make([]byte, n)), "Seal with a %d-byte nonce", n)
		_, err := aead.Open(nil, make([]byte, n), make([]byte, 32), nil)
		assert.ErrorIs(t, err, errGCMNonceLength, "Open with a %d-byte nonce", n)
	}

	nonce := randomBytes()[:aead.NonceSize()]
	ciphertext := aead.Seal(nil, nonce, []byte("plaintext"), []byte("aad"))
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, []byte("plaintext"), plaintext)
}

func TestNewGCMRejectsShortIVLength(t *testing.T) {
	key := gcmKey(t, func(cfg *Config) { cfg.GCMIVLength = 8 })
	_, err := key.NewGCM()
	assert.Error(t, err)
}

// SoftHSM does not generate GCM IVs. Configured as if it did, Seal must refuse to return
// ciphertext rather than encrypt every message under the same IV.
func TestGCMIVFromHSMNotGenerated(t *testing.T) {
	t.Run("NoIVBuffer", func(t *testing.T) {
		key := gcmKey(t, func(cfg *Config) { cfg.UseGCMIVFromHSM = true })
		aead, err := key.NewGCM()
		require.NoError(t, err)
		for _, nonce := range [][]byte{nil, make([]byte, aead.NonceSize())} {
			// SoftHSM2 encrypts under the empty IV, which Seal must catch. SoftHSMv3 rejects the
			// missing IV itself (CKR_MECHANISM_PARAM_INVALID), which is just as safe. Either way Seal
			// must panic rather than return ciphertext.
			err, _ := sealPanic(aead, nonce).(error)
			var p11Err pkcs11.Error
			assert.True(t, errors.Is(err, errGCMIVNotGenerated) || errors.As(err, &p11Err),
				"Seal with a %d-byte nonce: got %v, want errGCMIVNotGenerated or a token error", len(nonce), err)
		}
	})
	t.Run("IVBuffer", func(t *testing.T) {
		key := gcmKey(t, func(cfg *Config) {
			cfg.UseGCMIVFromHSM = true
			cfg.GCMIVFromHSMControl.SupplyIvForHSMGCMEncrypt = true
		})
		aead, err := key.NewGCM()
		require.NoError(t, err)
		nonce := make([]byte, aead.NonceSize())
		assert.Equal(t, errGCMIVNotGenerated, sealPanic(aead, nonce),
			"Seal returned ciphertext under an IV the token did not generate")
		assert.Equal(t, errGCMNonceLength, sealPanic(aead, nil))
	})
}

// TestGCMOutputLengthChecked checks that Open refuses a ciphertext shorter than the tag without
// asking the token, and that Seal and Open still accept the exact lengths they check for.
func TestGCMOutputLengthChecked(t *testing.T) {
	key := gcmKey(t, func(*Config) {})
	aead, err := key.NewGCM()
	require.NoError(t, err)
	nonce := make([]byte, aead.NonceSize())

	_, err = aead.Open(nil, nonce, make([]byte, aead.Overhead()-1), nil)
	require.ErrorIs(t, err, errAEADOutputLength)

	for _, plaintext := range [][]byte{nil, []byte("x"), make([]byte, 1000)} {
		sealed := aead.Seal(nil, nonce, plaintext, []byte("aad"))
		require.Len(t, sealed, len(plaintext)+aead.Overhead())
		opened, err := aead.Open(nil, nonce, sealed, []byte("aad"))
		require.NoError(t, err)
		require.Len(t, opened, len(plaintext))
	}
}
