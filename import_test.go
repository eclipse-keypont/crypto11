package crypto11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHardImportECDSA imports a software-generated key onto the token and proves the imported
// key is usable: it signs verifiably under its own public key, and FindKeyPair retrieves the same
// key by id and by label. crypto/ecdh covers P-256/384/521; P-224 is exercised separately below.
func TestHardImportECDSA(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	defer func() { require.NoError(t, ctx.Close()) }()

	importCurves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, curve := range importCurves {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		id := randomBytes()
		label := randomBytes()

		imported, err := ctx.ImportECDSAKeyPairWithLabel(id, label, key)
		require.NoError(t, err)
		require.NotNil(t, imported)
		defer func(k Signer) { _ = k.Delete() }(imported)

		// The handle's public key must be the one we imported.
		require.True(t, key.PublicKey.Equal(imported.Public()),
			"imported public key differs from source for %s", curve.Params().Name)

		// Signs verifiably, and is independently retrievable.
		testEcdsaSigning(t, imported, crypto.SHA256, curve.Params().Name, "SHA-256")

		byID, err := ctx.FindKeyPair(id, nil)
		require.NoError(t, err)
		require.NotNil(t, byID)
		testEcdsaSigning(t, byID.(crypto.Signer), crypto.SHA256, curve.Params().Name, "SHA-256")

		byLabel, err := ctx.FindKeyPair(nil, label)
		require.NoError(t, err)
		require.NotNil(t, byLabel)
	}
}

// TestHardImportECDSAUnsupportedCurve documents the one asymmetry with keygen: crypto/ecdh has no
// P-224, so a P-224 key cannot be imported and the failure is explicit rather than silent.
func TestHardImportECDSAUnsupportedCurve(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	defer func() { require.NoError(t, ctx.Close()) }()

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	_, err = ctx.ImportECDSAKeyPairWithLabel(randomBytes(), randomBytes(), key)
	require.Error(t, err)
}

// TestImportECDSANilKey rejects a nil key without touching the token.
func TestImportECDSANilKey(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	defer func() { require.NoError(t, ctx.Close()) }()

	_, err = ctx.ImportECDSAKeyPair(randomBytes(), nil)
	require.Error(t, err)
}
