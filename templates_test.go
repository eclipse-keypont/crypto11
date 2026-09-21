// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPrivateFollowsLoginSupport(t *testing.T) {
	assert.True(t, (&Context{cfg: &Config{}}).defaultPrivate())
	assert.False(t, (&Context{cfg: &Config{LoginNotSupported: true}}).defaultPrivate(),
		"a Context that never logs in could not reach a private object")
}

// ckaPrivate reads CKA_PRIVATE back from the token for the private or secret half of key.
func ckaPrivate(t *testing.T, ctx *Context, key interface{}) bool {
	t.Helper()
	attr, err := ctx.GetAttribute(key, CkaPrivate)
	require.NoError(t, err)
	require.NotNil(t, attr)
	require.Len(t, attr.Value, 1)
	return attr.Value[0] != 0
}

func TestGeneratedKeysArePrivateByDefault(t *testing.T) {
	withContext(t, func(ctx *Context) {
		rsaKey, err := ctx.GenerateRSAKeyPair(randomBytes(), rsaSize)
		require.NoError(t, err)
		defer func() { _ = rsaKey.Delete() }()
		assert.True(t, ckaPrivate(t, ctx, rsaKey), "RSA private key")

		ecKey, err := ctx.GenerateECDSAKeyPair(randomBytes(), elliptic.P256())
		require.NoError(t, err)
		defer func() { _ = ecKey.Delete() }()
		assert.True(t, ckaPrivate(t, ctx, ecKey), "ECDSA private key")

		secret, err := ctx.GenerateSecretKey(randomBytes(), 256, CipherAES)
		require.NoError(t, err)
		defer func() { _ = secret.Delete() }()
		assert.True(t, ckaPrivate(t, ctx, secret), "AES secret key")

		if mlkem, err := ctx.GenerateMLKEMKeyPair(randomBytes(), MLKEM768); err == nil {
			defer func() { _ = mlkem.Delete() }()
			assert.True(t, ckaPrivate(t, ctx, mlkem), "ML-KEM private key")
		} else {
			t.Logf("ML-KEM not available on this token: %v", err)
		}
	})
}

func TestExplicitCkaPrivateIsPreserved(t *testing.T) {
	// A caller who wants a public object says so; the default must not override it.
	withContext(t, func(ctx *Context) {
		public, err := NewAttributeSetWithID(randomBytes())
		require.NoError(t, err)
		private := public.Copy()
		require.NoError(t, private.Set(CkaPrivate, false))

		key, err := ctx.GenerateRSAKeyPairWithAttributes(public, private, rsaSize)
		require.NoError(t, err)
		defer func() { _ = key.Delete() }()
		assert.False(t, ckaPrivate(t, ctx, key))

		// And the template reflects what was applied.
		assert.Equal(t, []byte{0}, private[CkaPrivate].Value)
	})
}
