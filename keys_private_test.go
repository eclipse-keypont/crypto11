// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// publicObjectAttributes returns a template for a key that is a public object (CKA_PRIVATE =
// false) with the given id and label. Many tokens let a session create such an object without
// logging in.
func publicObjectAttributes(t *testing.T, id, label []byte) AttributeSet {
	t.Helper()
	attrs, err := NewAttributeSetWithIDAndLabel(id, label)
	require.NoError(t, err)
	require.NoError(t, attrs.Set(pkcs11.CKA_PRIVATE, false))
	return attrs
}

// TestSecretKeyFindersRequirePrivateObject checks that the secret-key finders pass over a key
// that is a public object, unless the caller asks for CKA_PRIVATE explicitly, and find the
// private key that carries the same label.
func TestSecretKeyFindersRequirePrivateObject(t *testing.T) {
	withContext(t, func(ctx *Context) {
		label := randomBytes()
		public, err := ctx.GenerateSecretKeyWithAttributes(publicObjectAttributes(t, randomBytes(), label), 256, CipherAES)
		require.NoError(t, err)
		defer func() { _ = public.Delete() }()

		_, err = ctx.FindKey(nil, label)
		require.Error(t, err, "FindKey returned a secret key with CKA_PRIVATE = false")
		keys, err := ctx.FindKeys(nil, label)
		require.NoError(t, err)
		require.Empty(t, keys, "FindKeys returned a secret key with CKA_PRIVATE = false")

		explicit := NewAttributeSet()
		require.NoError(t, explicit.Set(pkcs11.CKA_LABEL, label))
		require.NoError(t, explicit.Set(pkcs11.CKA_PRIVATE, false))
		keys, err = ctx.FindKeysWithAttributes(explicit)
		require.NoError(t, err)
		require.Len(t, keys, 1, "an explicit CKA_PRIVATE = false must still find the key")

		private, err := ctx.GenerateSecretKeyWithLabel(randomBytes(), label, 256, CipherAES)
		require.NoError(t, err)
		defer func() { _ = private.Delete() }()
		got, err := ctx.FindKey(nil, label)
		require.NoError(t, err)
		require.Equal(t, private.handle, got.handle)
	})
}

// TestPrivateKeyFindersRequirePrivateObject checks the same for the private-key and key-pair
// finders: a key pair whose private half is a public object is not returned.
func TestPrivateKeyFindersRequirePrivateObject(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id, label := randomBytes(), randomBytes()
		pub, err := NewAttributeSetWithIDAndLabel(id, label)
		require.NoError(t, err)
		kp, err := ctx.GenerateRSAKeyPairWithAttributes(pub, publicObjectAttributes(t, id, label), rsaSize)
		if err != nil {
			t.Skipf("token refuses a private key with CKA_PRIVATE = false: %v", err)
		}
		defer func() { _ = kp.Delete() }()

		_, err = ctx.FindKeyPair(nil, label)
		require.Error(t, err, "FindKeyPair returned a key pair whose private half is a public object")
		_, err = ctx.FindRSAKeyPair(nil, label)
		require.Error(t, err, "FindRSAKeyPair returned a key pair whose private half is a public object")
		_, err = ctx.FindPrivateKey(nil, label)
		require.Error(t, err, "FindPrivateKey returned a private key that is a public object")
		all, err := ctx.FindAllKeyPairs()
		require.NoError(t, err)
		requireKeysAbsent(t, ctx, all, [][]byte{id}, "FindAllKeyPairs returned a key pair whose private half is a public object")

		mlkemID, mlkemLabel := randomBytes(), randomBytes()
		mlkemPub, err := NewAttributeSetWithIDAndLabel(mlkemID, mlkemLabel)
		require.NoError(t, err)
		mlkem, err := ctx.GenerateMLKEMKeyPairWithAttributes(mlkemPub, publicObjectAttributes(t, mlkemID, mlkemLabel), MLKEM768)
		if err != nil {
			t.Logf("no ML-KEM key pair with a public private half: %v", err)
			return
		}
		defer func() { _ = mlkem.Delete() }()
		_, err = ctx.FindMLKEMKeyPair(nil, mlkemLabel)
		require.Error(t, err, "FindMLKEMKeyPair returned a key pair whose private half is a public object")
	})
}

// TestSingleKeyFindersRefuseAmbiguousMatch checks that a finder for a single key reports an
// error when more than one key matches, instead of returning whichever the token listed first.
func TestSingleKeyFindersRefuseAmbiguousMatch(t *testing.T) {
	withContext(t, func(ctx *Context) {
		label := randomBytes()
		for range 2 {
			k, err := ctx.GenerateSecretKeyWithLabel(randomBytes(), label, 256, CipherAES)
			require.NoError(t, err)
			defer func(k *SecretKey) { _ = k.Delete() }(k)
		}
		_, err := ctx.FindKey(nil, label)
		require.ErrorIs(t, err, errAmbiguousKey)
		keys, err := ctx.FindKeys(nil, label)
		require.NoError(t, err)
		require.Len(t, keys, 2)

		pairLabel := randomBytes()
		for range 2 {
			kp, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), pairLabel, rsaSize)
			require.NoError(t, err)
			defer func(kp SignerDecrypter) { _ = kp.Delete() }(kp)
		}
		_, err = ctx.FindKeyPair(nil, pairLabel)
		require.ErrorIs(t, err, errAmbiguousKey)
		_, err = ctx.FindRSAKeyPair(nil, pairLabel)
		require.ErrorIs(t, err, errAmbiguousKey)
		_, err = ctx.FindPrivateKey(nil, pairLabel)
		require.ErrorIs(t, err, errAmbiguousKey)
	})
}

// TestRequirePrivateObjectWithoutLogin checks that a Context that never logs in does not
// require CKA_PRIVATE = true, since it cannot see private objects at all.
func TestRequirePrivateObjectWithoutLogin(t *testing.T) {
	for _, c := range []struct {
		loginNotSupported bool
		want              bool
	}{{false, true}, {true, false}} {
		ctx := &Context{cfg: &Config{LoginNotSupported: c.loginNotSupported}}
		attrs := NewAttributeSet()
		require.NoError(t, ctx.requirePrivateObject(attrs))
		_, set := attrs[pkcs11.CKA_PRIVATE]
		require.Equal(t, c.want, set, "LoginNotSupported=%v", c.loginNotSupported)
	}
}
