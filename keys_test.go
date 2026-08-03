// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withContext executes a test function with a context.
func withContext(t *testing.T, f func(ctx *Context)) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	f(ctx)
}

func TestFindKeysRequiresIdOrLabel(t *testing.T) {
	withContext(t, func(ctx *Context) {
		_, err := ctx.FindKey(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeys(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeyPair(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindKeyPairs(nil, nil)
		assert.Error(t, err)
	})
}

func TestFindingKeysWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		label := randomBytes()
		label2 := randomBytes()

		key, err := ctx.GenerateSecretKeyWithLabel(randomBytes(), label, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label2, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(randomBytes(), label2, 256, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 16)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 32)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})
}

func TestFindingKeyPairsWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {

		// Note: we use common labels, not IDs in this test code. AWS CloudHSM
		// does not accept two keys with the same ID.

		label := randomBytes()
		label2 := randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		_ = attrs.Set(CkaKeyType, pkcs11.CKK_RSA)
		keys, err = ctx.FindKeyPairsWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 3)
	})
}

func TestFindingAllKeys(t *testing.T) {
	withContext(t, func(ctx *Context) {
		for i := 0; i < 10; i++ {
			id := randomBytes()
			key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
			require.NoError(t, err)

			defer func(k *SecretKey) { _ = k.Delete() }(key)
		}

		keys, err := ctx.FindAllKeys()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 10)
	})
}

func TestFindingAllKeyPairs(t *testing.T) {
	withContext(t, func(ctx *Context) {
		for i := 1; i <= 5; i++ {
			id := randomBytes()
			key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
			require.NoError(t, err)

			defer func(k Signer) { _ = k.Delete() }(key)
		}

		keys, err := ctx.FindAllKeyPairs()
		require.NoError(t, err)
		require.NotNil(t, keys)

		require.Len(t, keys, 5)
	})
}

func TestGettingPrivateKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaModulus})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Len(t, attrs[CkaModulus].Value, 256)
	})
}

func TestGettingPublicKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs, err := ctx.GetPubAttributes(key, []AttributeType{CkaModulusBits})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(rsaSize), pkcs11.BytesToULong(attrs[CkaModulusBits].Value))
	})
}

func TestGettingSecretKeyAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()

		key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		attrs, err := ctx.GetAttributes(key, []AttributeType{CkaValueLen})
		require.NoError(t, err)
		require.NotNil(t, attrs)
		require.Len(t, attrs, 1)

		require.Equal(t, uint(16), pkcs11.BytesToULong(attrs[CkaValueLen].Value))
	})
}

func TestGettingUnsupportedKeyTypeAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		key, err := rsa.GenerateKey(rand.Reader, rsaSize)
		require.NoError(t, err)

		_, err = ctx.GetAttributes(key, []AttributeType{CkaModulusBits})
		require.Error(t, err)
	})
}
