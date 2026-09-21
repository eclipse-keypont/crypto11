// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
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
	ctx := testContext(t)

	f(ctx)
}

// foundIDs indexes keys by their CKA_ID. Objects whose CKA_ID cannot be read were not created
// by the calling test, so they are skipped rather than failing it.
func foundIDs[T any](t *testing.T, ctx *Context, keys []T) map[string]bool {
	t.Helper()

	ids := make(map[string]bool, len(keys))
	for _, key := range keys {
		attr, err := ctx.GetAttribute(key, CkaId)
		if err != nil {
			continue
		}
		ids[string(attr.Value)] = true
	}

	return ids
}

// requireKeysFound checks that every wanted CKA_ID appears in got. The token may already hold
// keys the test did not create, so the assertion is containment rather than an exact count.
func requireKeysFound[T any](t *testing.T, ctx *Context, got []T, want [][]byte, msg string) {
	t.Helper()

	require.GreaterOrEqual(t, len(got), len(want), msg)

	found := foundIDs(t, ctx, got)
	for _, id := range want {
		assert.True(t, found[string(id)], "%s: omitted the key with ID %x", msg, id)
	}
}

// requireKeysAbsent checks that none of the unwanted CKA_IDs appear in got, so that a search
// narrowed by attributes is still shown to exclude the keys it should exclude.
func requireKeysAbsent[T any](t *testing.T, ctx *Context, got []T, unwanted [][]byte, msg string) {
	t.Helper()

	found := foundIDs(t, ctx, got)
	for _, id := range unwanted {
		assert.False(t, found[string(id)], "%s: returned the key with ID %x", msg, id)
	}
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

		_, err = ctx.FindPrivateKey(nil, nil)
		assert.Error(t, err)

		_, err = ctx.FindPrivateKeys(nil, nil)
		assert.Error(t, err)
	})
}

func TestFindingKeysWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {
		label := randomBytes()
		label2 := randomBytes()

		// The labels are unique to this run, so searches by label can be counted exactly. The
		// searches by key length cannot: they match every AES key on the token, including any
		// this test did not create, and so are asserted by ID instead.
		id128a, id128b, id256 := randomBytes(), randomBytes(), randomBytes()

		key, err := ctx.GenerateSecretKeyWithLabel(id128a, label, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(id128b, label2, 128, CipherAES)
		require.NoError(t, err)
		defer func(k *SecretKey) { _ = k.Delete() }(key)

		key, err = ctx.GenerateSecretKeyWithLabel(id256, label2, 256, CipherAES)
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
		requireKeysFound(t, ctx, keys, [][]byte{id128a, id128b}, "FindKeysWithAttributes(CkaValueLen=16)")
		requireKeysAbsent(t, ctx, keys, [][]byte{id256}, "FindKeysWithAttributes(CkaValueLen=16)")

		attrs = NewAttributeSet()
		err = attrs.Set(CkaValueLen, 32)
		require.NoError(t, err)

		keys, err = ctx.FindKeysWithAttributes(attrs)
		require.NoError(t, err)
		requireKeysFound(t, ctx, keys, [][]byte{id256}, "FindKeysWithAttributes(CkaValueLen=32)")
		requireKeysAbsent(t, ctx, keys, [][]byte{id128a, id128b}, "FindKeysWithAttributes(CkaValueLen=32)")
	})
}

func TestFindingKeyPairsWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {

		// Note: we use common labels, not IDs in this test code. AWS CloudHSM
		// does not accept two keys with the same ID.

		label := randomBytes()
		label2 := randomBytes()

		// The labels are unique to this run, so searches by label can be counted exactly. The
		// search by key type cannot: it matches every RSA key pair on the token, including any
		// this test did not create, and so is asserted by ID instead.
		id1, id2, id3 := randomBytes(), randomBytes(), randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(id1, label, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(id2, label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(id3, label2, rsaSize)
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
		requireKeysFound(t, ctx, keys, [][]byte{id1, id2, id3}, "FindKeyPairsWithAttributes(CkaKeyType=CKK_RSA)")
	})
}

func TestFindingPrivateKeysWithAttributes(t *testing.T) {
	withContext(t, func(ctx *Context) {

		// Note: we use common labels, not IDs in this test code. AWS CloudHSM
		// does not accept two keys with the same ID.

		label := randomBytes()
		label2 := randomBytes()

		// The labels are unique to this run, so searches by label can be counted exactly. The
		// search by key type cannot: it matches every RSA private key on the token, including
		// any this test did not create, and so is asserted by ID instead.
		id1, id2, id3 := randomBytes(), randomBytes(), randomBytes()

		key, err := ctx.GenerateRSAKeyPairWithLabel(id1, label, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(id2, label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		key, err = ctx.GenerateRSAKeyPairWithLabel(id3, label2, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, label)
		keys, err := ctx.FindPrivateKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		_ = attrs.Set(CkaLabel, label2)
		keys, err = ctx.FindPrivateKeysWithAttributes(attrs)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		attrs = NewAttributeSet()
		_ = attrs.Set(CkaKeyType, pkcs11.CKK_RSA)
		keys, err = ctx.FindPrivateKeysWithAttributes(attrs)
		require.NoError(t, err)
		requireKeysFound(t, ctx, keys, [][]byte{id1, id2, id3}, "FindPrivateKeysWithAttributes(CkaKeyType=CKK_RSA)")
	})
}

// TestFindingPrivateKeyNotFound pins the current not-found behaviour: the
// singular lookups report an error rather than returning a nil PrivateKey.
func TestFindingPrivateKeyNotFound(t *testing.T) {
	withContext(t, func(ctx *Context) {
		_, err := ctx.FindPrivateKey(randomBytes(), nil)
		assert.Error(t, err)

		attrs := NewAttributeSet()
		_ = attrs.Set(CkaLabel, randomBytes())
		_, err = ctx.FindPrivateKeyWithAttributes(attrs)
		assert.Error(t, err)

		// The plural flavours report no error, just an empty result.
		keys, err := ctx.FindPrivateKeys(randomBytes(), nil)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

func TestFindingAllKeys(t *testing.T) {
	withContext(t, func(ctx *Context) {
		const count = 10

		// Identify the keys by their CKA_ID, not by counting: the token may already hold keys
		// that this test did not create and must not assume anything about.
		want := make([][]byte, 0, count)

		for i := 0; i < count; i++ {
			id := randomBytes()
			key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
			require.NoError(t, err)

			defer func(k *SecretKey) { _ = k.Delete() }(key)

			want = append(want, id)
		}

		keys, err := ctx.FindAllKeys()
		require.NoError(t, err)
		require.NotNil(t, keys)

		requireKeysFound(t, ctx, keys, want, "FindAllKeys")
	})
}

func TestFindingAllKeyPairs(t *testing.T) {
	withContext(t, func(ctx *Context) {
		const count = 5

		// Identify the key pairs by their CKA_ID, not by counting: the token may already hold
		// key pairs that this test did not create and must not assume anything about.
		want := make([][]byte, 0, count)

		for i := 0; i < count; i++ {
			id := randomBytes()
			key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
			require.NoError(t, err)

			defer func(k Signer) { _ = k.Delete() }(key)

			want = append(want, id)
		}

		keys, err := ctx.FindAllKeyPairs()
		require.NoError(t, err)
		require.NotNil(t, keys)

		requireKeysFound(t, ctx, keys, want, "FindAllKeyPairs")
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

func TestAttributeAccessorsRejectForeignContext(t *testing.T) {
	// Two Contexts on the same token, so the handle would in fact resolve on
	// the other one — the accessor must refuse on principle, not by luck of
	// the handle being invalid there.
	ctx1 := testContext(t)
	defer ctx1.Close()
	ctx2 := testContext(t)
	defer ctx2.Close()

	key, err := ctx1.GenerateRSAKeyPair(randomBytes(), rsaSize)
	require.NoError(t, err)
	defer func(k Signer) { _ = k.Delete() }(key)

	_, err = ctx2.GetAttributes(key, []AttributeType{CkaModulus})
	require.ErrorIs(t, err, errForeignKey)
	_, err = ctx2.GetAttribute(key, CkaModulus)
	require.ErrorIs(t, err, errForeignKey)
	_, err = ctx2.GetPubAttributes(key, []AttributeType{CkaModulusBits})
	require.ErrorIs(t, err, errForeignKey)
	_, err = ctx2.GetPubAttribute(key, CkaModulusBits)
	require.ErrorIs(t, err, errForeignKey)

	secret, err := ctx1.GenerateSecretKey(randomBytes(), 256, CipherAES)
	require.NoError(t, err)
	defer func(k *SecretKey) { _ = k.Delete() }(secret)
	_, err = ctx2.GetAttributes(secret, []AttributeType{CkaValueLen})
	require.ErrorIs(t, err, errForeignKey)

	// The owning Context is unaffected.
	_, err = ctx1.GetAttributes(key, []AttributeType{CkaModulus})
	require.NoError(t, err)
}

// destroyPrivateKeysWithLabel removes private keys the finders deliberately no longer return.
func destroyPrivateKeysWithLabel(t *testing.T, ctx *Context, label []byte) {
	t.Helper()
	err := ctx.withSession(func(session *pkcs11Session) error {
		handles, err := findKeys(session, nil, label, uintPtr(pkcs11.CKO_PRIVATE_KEY), nil)
		if err != nil {
			return err
		}
		for _, h := range handles {
			if err := session.ctx.DestroyObject(session.handle, h); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
}

func TestLabelOnlyPrivateKeyIsNotPairedWithStranger(t *testing.T) {
	withContext(t, func(ctx *Context) {
		// A bystander key pair: the "first RSA public key on the token" the old
		// fallback would have grabbed.
		stranger, err := ctx.GenerateRSAKeyPair(randomBytes(), rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(stranger)

		// A private key with a label but no CKA_ID, whose public half carries a
		// different label and an id — nothing links the two by label or id.
		orphanLabel := []byte("orphan-" + string(randomBytes()))
		public := NewAttributeSet()
		require.NoError(t, public.Set(CkaId, randomBytes()))
		require.NoError(t, public.Set(CkaLabel, []byte("pub-of-"+string(orphanLabel))))
		private := NewAttributeSet()
		require.NoError(t, private.Set(CkaLabel, orphanLabel))
		orphan, err := ctx.GenerateRSAKeyPairWithAttributes(public, private, rsaSize)
		require.NoError(t, err)
		defer destroyPrivateKeysWithLabel(t, ctx, orphanLabel)
		defer func(k Signer) { _ = k.Delete() }(orphan)

		// The finders must not manufacture a Signer out of the orphan and a
		// public key that is not its own.
		found, err := ctx.FindKeyPairs(nil, orphanLabel)
		require.NoError(t, err)
		require.Empty(t, found, "a label-only private key without a matching public half must not be returned")

		_, err = ctx.FindKeyPair(nil, orphanLabel)
		require.Error(t, err)

		// Enumeration skips it rather than failing.
		_, err = ctx.FindAllKeyPairs()
		require.NoError(t, err)
	})
}

func TestLabelOnlyKeyPairWithMatchingLabelsStillFound(t *testing.T) {
	// The fix must not break the legitimate label-only case: both halves share
	// a label and neither has an id.
	withContext(t, func(ctx *Context) {
		label := []byte("pair-" + string(randomBytes()))
		public := NewAttributeSet()
		require.NoError(t, public.Set(CkaLabel, label))
		private := NewAttributeSet()
		require.NoError(t, private.Set(CkaLabel, label))
		key, err := ctx.GenerateRSAKeyPairWithAttributes(public, private, rsaSize)
		require.NoError(t, err)
		defer func(k Signer) { _ = k.Delete() }(key)

		found, err := ctx.FindKeyPair(nil, label)
		require.NoError(t, err)
		require.Equal(t, key.Public(), found.Public())
	})
}
