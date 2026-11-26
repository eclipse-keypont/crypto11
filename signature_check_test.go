// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestECDSASignatureCheck checks that a signature is verified before release: a good one passes,
// one that does not verify is refused, and a key without a known public half is not checked.
func TestECDSASignatureCheck(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("message"))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	require.NoError(t, checkECDSASignature(&key.PublicKey, digest[:], sig))
	other := sha256.Sum256([]byte("another message"))
	require.ErrorIs(t, checkECDSASignature(&key.PublicKey, other[:], sig), errSignatureCheck)
	require.NoError(t, checkECDSASignature(nil, other[:], sig))
}

// TestEd25519SignatureCheck is TestECDSASignatureCheck for Ed25519.
func TestEd25519SignatureCheck(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, []byte("message"))

	require.NoError(t, checkEd25519Signature(pub, []byte("message"), sig))
	require.ErrorIs(t, checkEd25519Signature(pub, []byte("another message"), sig), errSignatureCheck)
	require.NoError(t, checkEd25519Signature(nil, []byte("another message"), sig))
}

// signer is what both a key pair and a private key found alone can do.
type signer interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// TestSignersCheckWithFoundKeys signs with ECDSA and Ed25519 keys found as pairs and alone, so
// that every path runs its signature check against a real token.
func TestSignersCheckWithFoundKeys(t *testing.T) {
	ctx := testContext(t)
	digest := sha256.Sum256([]byte("message"))

	id := randomBytes()
	pair, err := ctx.GenerateECDSAKeyPair(id, elliptic.P256())
	require.NoError(t, err)
	t.Cleanup(func() { _ = pair.Delete() })
	alone, err := ctx.FindPrivateKey(id, nil)
	require.NoError(t, err)
	for _, signer := range []signer{pair, alone} {
		sig, err := signer.Sign(rand.Reader, digest[:], nil)
		require.NoError(t, err)
		require.True(t, ecdsa.VerifyASN1(pair.Public().(*ecdsa.PublicKey), digest[:], sig))
	}

	edID := randomBytes()
	edPair, err := ctx.GenerateEd25519KeyPair(edID)
	if err != nil {
		t.Skipf("no Ed25519: %v", err)
	}
	t.Cleanup(func() { _ = edPair.Delete() })
	edAlone, err := ctx.FindPrivateKey(edID, nil)
	require.NoError(t, err)
	for _, signer := range []signer{edPair, edAlone} {
		sig, err := signer.Sign(rand.Reader, []byte("message"), &ed25519.Options{})
		require.NoError(t, err)
		require.True(t, ed25519.Verify(edPair.Public().(ed25519.PublicKey), []byte("message"), sig))
	}
}
