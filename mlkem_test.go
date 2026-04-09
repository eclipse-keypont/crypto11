// Copyright 2026 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"testing"

	"github.com/miekg/pkcs11"
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
	ctx, err := ConfigureFromFile("config")
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
