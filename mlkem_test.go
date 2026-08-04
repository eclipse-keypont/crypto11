// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mlkemSharedSecretTemplate returns a standard shared-secret template: a session-only,
// extractable AES-256 key suitable for round-trip testing.
func mlkemSharedSecretTemplate() AttributeSet {
	a := NewAttributeSet()
	_ = a.Set(CkaClass, pkcs11.CKO_SECRET_KEY)
	_ = a.Set(CkaKeyType, pkcs11.CKK_AES)
	_ = a.Set(CkaValueLen, 32)
	_ = a.Set(CkaToken, false)
	_ = a.Set(CkaSensitive, false)
	_ = a.Set(CkaExtractable, true)
	return a
}

func TestMLKEM(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)
	defer func() { _ = ctx.Close() }()

	skipIfMechUnsupported(t, ctx, pkcs11.CKM_ML_KEM_KEY_PAIR_GEN)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_ML_KEM)

	t.Run("Generate512", func(t *testing.T) { testMLKEMGenerate(t, ctx, MLKEM512) })
	t.Run("Generate768", func(t *testing.T) { testMLKEMGenerate(t, ctx, MLKEM768) })
	t.Run("Generate1024", func(t *testing.T) { testMLKEMGenerate(t, ctx, MLKEM1024) })
	t.Run("RoundTrip", func(t *testing.T) { testMLKEMRoundTrip(t, ctx) })
	t.Run("FindByID", func(t *testing.T) { testMLKEMFindByID(t, ctx) })
	t.Run("FindByLabel", func(t *testing.T) { testMLKEMFindByLabel(t, ctx) })
	t.Run("Delete", func(t *testing.T) { testMLKEMDelete(t, ctx) })
	t.Run("OtherFindersStillWork", func(t *testing.T) { testMLKEMOtherFindersStillWork(t, ctx) })
}

func testMLKEMGenerate(t *testing.T, ctx *Context, paramSet MLKEMParameterSet) {
	t.Helper()
	id := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPair(id, paramSet)
	require.NoError(t, err)
	require.NotNil(t, key)
	defer func() { _ = key.Delete() }()

	assert.Equal(t, paramSet, key.ParameterSet())
}

func testMLKEMRoundTrip(t *testing.T, ctx *Context) {
	t.Helper()
	id := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPair(id, MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	ssTemplate := mlkemSharedSecretTemplate()

	// Encapsulate: produce a ciphertext and a shared secret using the public key.
	ciphertext, encapSS, err := key.Encapsulate(ssTemplate)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	defer func() { _ = encapSS.Delete() }()

	// Decapsulate: recover the shared secret from the ciphertext using the private key.
	decapSS, err := key.Decapsulate(ciphertext, ssTemplate)
	require.NoError(t, err)
	defer func() { _ = decapSS.Delete() }()

	// Both sides must derive the same shared secret.
	encapBytes, err := encapSS.Bytes()
	require.NoError(t, err)
	decapBytes, err := decapSS.Bytes()
	require.NoError(t, err)

	assert.Equal(t, encapBytes, decapBytes, "encapsulated and decapsulated shared secrets must match")
	assert.Len(t, encapBytes, 32, "shared secret should be 32 bytes for AES-256 template")
}

func testMLKEMFindByID(t *testing.T, ctx *Context) {
	t.Helper()
	id := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPair(id, MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	found, err := ctx.FindMLKEMKeyPair(id, nil)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, MLKEM768, found.ParameterSet())
}

func testMLKEMFindByLabel(t *testing.T, ctx *Context) {
	t.Helper()
	id := randomBytes()
	label := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPairWithLabel(id, label, MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	found, err := ctx.FindMLKEMKeyPair(nil, label)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, MLKEM768, found.ParameterSet())
}

// testMLKEMOtherFindersStillWork checks that an ML-KEM key pair sitting on the token does not
// abort enumeration of the key types this package does support. Finders skip keys they cannot
// represent instead of returning "unsupported key type".
func testMLKEMOtherFindersStillWork(t *testing.T, ctx *Context) {
	t.Helper()

	mlkemKey, err := ctx.GenerateMLKEMKeyPair(randomBytes(), MLKEM768)
	require.NoError(t, err)
	defer func() { _ = mlkemKey.Delete() }()

	label := randomBytes()
	rsaKey, err := ctx.GenerateRSAKeyPairWithLabel(randomBytes(), label, rsaSize)
	require.NoError(t, err)
	defer func() { _ = rsaKey.Delete() }()

	pairs, err := ctx.FindAllKeyPairs()
	require.NoError(t, err, "an ML-KEM key pair must not abort key pair enumeration")
	assert.NotEmpty(t, pairs)

	found, err := ctx.FindKeyPair(nil, label)
	require.NoError(t, err)
	assert.NotNil(t, found)

	privKeys, err := ctx.FindPrivateKeysWithAttributes(NewAttributeSet())
	require.NoError(t, err, "an ML-KEM private key must not abort private key enumeration")
	assert.NotEmpty(t, privKeys)

	rsaPairs, err := ctx.FindRSAKeyPairsWithAttributes(NewAttributeSet())
	require.NoError(t, err, "an ML-KEM key pair must not abort RSA key pair enumeration")
	assert.NotEmpty(t, rsaPairs)

	allRSAPairs, err := ctx.FindAllRSAKeyPairs()
	require.NoError(t, err, "an ML-KEM key pair must not abort FindAllRSAKeyPairs")
	assert.NotEmpty(t, allRSAPairs)
}

func testMLKEMDelete(t *testing.T, ctx *Context) {
	t.Helper()
	id := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPair(id, MLKEM768)
	require.NoError(t, err)

	require.NoError(t, key.Delete())

	pairs, err := ctx.FindMLKEMKeyPairs(id, nil)
	require.NoError(t, err)
	assert.Empty(t, pairs, "key pair should be gone after Delete")
}
