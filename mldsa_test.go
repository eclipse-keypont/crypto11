//go:build go1.27

package crypto11

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"io"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mldsaContext(t *testing.T) *Context {
	t.Helper()
	ctx := testContext(t)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_ML_DSA)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_HASH_ML_DSA)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_ML_DSA_KEY_PAIR_GEN)
	return ctx
}

func TestGenerateMLDSAKeyPair(t *testing.T) {
	ctx := mldsaContext(t)

	tests := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"ML-DSA-44", mldsa.MLDSA44()},
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := randomBytes()

			key, err := ctx.GenerateMLDSAKeyPair(id, tc.params)
			require.NoError(t, err)
			require.NotNil(t, key)
			t.Cleanup(func() { _ = key.Delete() })

			pub, ok := key.Public().(*mldsa.PublicKey)
			require.True(t, ok, "expected *mldsa.PublicKey, got %T", key.Public())

			testMLDSASigning(t, key, pub)

			key2, err := ctx.FindKeyPair(id, nil)
			require.NoError(t, err)
			require.IsType(t, &pkcs11PrivateKeyMLDSA{}, key2)
			assert.Equal(t, pub, key2.Public(), "the key found by id must export the same public key")
			testMLDSASigning(t, key2, pub)
		})
	}
}

func TestGenerateMLDSAKeyPairWithLabel(t *testing.T) {
	ctx := mldsaContext(t)

	tests := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"ML-DSA-44", mldsa.MLDSA44()},
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := randomBytes()
			label := randomBytes()

			key, err := ctx.GenerateMLDSAKeyPairWithLabel(id, label, tc.params)
			require.NoError(t, err)
			require.NotNil(t, key)
			t.Cleanup(func() { _ = key.Delete() })

			pub, ok := key.Public().(*mldsa.PublicKey)
			require.True(t, ok, "expected *mldsa.PublicKey, got %T", key.Public())

			testMLDSASigning(t, key, pub)

			key2, err := ctx.FindKeyPair(id, nil)
			require.NoError(t, err)
			require.IsType(t, &pkcs11PrivateKeyMLDSA{}, key2)
			assert.Equal(t, pub, key2.Public(), "the key found by id must export the same public key")
			testMLDSASigning(t, key2, pub)

			key3, err := ctx.FindKeyPair(nil, label)
			require.NoError(t, err)
			require.IsType(t, &pkcs11PrivateKeyMLDSA{}, key3)
			assert.Equal(t, pub, key3.Public(), "the key found by id must export the same public key")
			testMLDSASigning(t, key3, pub)

			key4, err := ctx.FindKeyPair(id, label)
			require.NoError(t, err)
			require.IsType(t, &pkcs11PrivateKeyMLDSA{}, key4)
			assert.Equal(t, pub, key4.Public(), "the key found by id must export the same public key")
			testMLDSASigning(t, key4, pub)
		})
	}
}

func testMLDSASigning(t *testing.T, key crypto.Signer, pub *mldsa.PublicKey) {
	t.Helper()

	message := []byte("sign me with ML-DSA")

	for name, opts := range map[string]crypto.SignerOpts{
		"nil":            nil,
		"crypto.Hash(0)": crypto.Hash(0),
		"mldsa.Options{}": &mldsa.Options{
			Context: "the signing context",
		},
	} {
		var verifyOptions *mldsa.Options
		if o, ok := opts.(*mldsa.Options); ok {
			verifyOptions = o
		}

		sig1, err := key.Sign(rand.Reader, message, opts)
		require.NoError(t, err, "Sigh with opts %s", name)
		assert.NoError(t, mldsa.Verify(pub, message, sig1, verifyOptions), "opts %s: signature failed to verify", name)
		assert.Len(t, sig1, pub.Parameters().SignatureSize())

		sig2, err := key.Sign(rand.Reader, message, opts)
		require.NoError(t, err, "Sigh with opts %s", name)
		assert.NoError(t, mldsa.Verify(pub, message, sig2, verifyOptions), "opts %s: signature failed to verify", name)
		assert.Len(t, sig2, pub.Parameters().SignatureSize())
		assert.NotEqual(t, sig1, sig2)

		// SignDeterministic
		keyDet, ok := key.(interface {
			SignDeterministic([]byte, crypto.SignerOpts) ([]byte, error)
		})
		require.True(t, ok)

		sig1, err = keyDet.SignDeterministic(message, opts)
		require.NoError(t, err, "SignDeterministic with opts %s", name)
		assert.NoError(t, mldsa.Verify(pub, message, sig1, verifyOptions), "opts %s: signature failed to verify", name)
		assert.Len(t, sig1, pub.Parameters().SignatureSize())

		sig2, err = keyDet.SignDeterministic(message, opts)
		require.NoError(t, err, "SignDeterministic with opts %s", name)
		assert.Equal(t, sig1, sig2)

		// External Mu
		mu := make([]byte, 64)
		io.ReadFull(rand.Reader, mu)
		_, err = key.Sign(rand.Reader, mu, crypto.MLDSAMu)
		assert.Error(t, err)

		// Unsupported
		_, err = key.Sign(rand.Reader, mu, crypto.SHA512)
		assert.Error(t, err)
	}
}
