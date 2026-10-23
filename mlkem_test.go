// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mlkemSharedSecretTemplate returns a standard shared-secret template: a session-only,
// extractable AES-256 key suitable for round-trip testing.
func mlkemSharedSecretTemplate() AttributeSet {
	a := NewAttributeSet()
	_ = a.Set(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY)
	_ = a.Set(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES)
	_ = a.Set(pkcs11.CKA_VALUE_LEN, 32)
	_ = a.Set(pkcs11.CKA_TOKEN, false)
	_ = a.Set(pkcs11.CKA_SENSITIVE, false)
	_ = a.Set(pkcs11.CKA_EXTRACTABLE, true)
	return a
}

func TestMLKEM(t *testing.T) {
	ctx := testContext(t)

	skipIfMechUnsupported(t, ctx, pkcs11.CKM_ML_KEM_KEY_PAIR_GEN)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_ML_KEM)

	t.Run("Generate512", func(t *testing.T) { testMLKEMGenerate(t, ctx, MLKEM512) })
	t.Run("Generate768", func(t *testing.T) { testMLKEMGenerate(t, ctx, MLKEM768) })
	t.Run("Generate1024", func(t *testing.T) { testMLKEMGenerate(t, ctx, MLKEM1024) })
	t.Run("RoundTrip", func(t *testing.T) { testMLKEMRoundTrip(t, ctx) })
	t.Run("EncapsulatorBytesInterop", func(t *testing.T) { testMLKEMEncapsulatorBytesInterop(t, ctx) })
	t.Run("EncapsulatorByAESGCM", func(t *testing.T) { testMLKEMEncapsulatorByAESGCM(t, ctx) })
	t.Run("FindByID", func(t *testing.T) { testMLKEMFindByID(t, ctx) })
	t.Run("FindByLabel", func(t *testing.T) { testMLKEMFindByLabel(t, ctx) })
	t.Run("Delete", func(t *testing.T) { testMLKEMDelete(t, ctx) })
	t.Run("OtherFindersStillWork", func(t *testing.T) { testMLKEMOtherFindersStillWork(t, ctx) })
	t.Run("NonExtractableSecretIsAnError", func(t *testing.T) { testMLKEMNonExtractableSecret(t, ctx) })
	t.Run("SharedSecretDefaults", func(t *testing.T) { testMLKEMSharedSecretDefaults(t, ctx) })
	t.Run("FindRejectsPlantedPublicKey", func(t *testing.T) { testMLKEMFindRejectsPlantedPublicKey(t, ctx) })
	t.Run("LabelOnlyKeyNotPairedWithForeignKey", func(t *testing.T) { testMLKEMLabelOnlyKey(t, ctx) })
}

// A shared-secret template that leaves CKA_SENSITIVE and CKA_EXTRACTABLE out must still produce
// a sensitive, non-extractable key, whatever the token's own defaults are.
func testMLKEMSharedSecretDefaults(t *testing.T, ctx *Context) {
	t.Helper()
	key, err := ctx.GenerateMLKEMKeyPair(randomBytes(), MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	template := NewAttributeSet()
	require.NoError(t, template.Set(CkaClass, pkcs11.CKO_SECRET_KEY))
	require.NoError(t, template.Set(CkaKeyType, pkcs11.CKK_AES))
	require.NoError(t, template.Set(CkaValueLen, 32))
	require.NoError(t, template.Set(CkaToken, false))

	ciphertext, encapSS, err := key.Encapsulate(template)
	require.NoError(t, err)
	defer func() { _ = encapSS.Delete() }()
	decapSS, err := key.Decapsulate(ciphertext, template)
	require.NoError(t, err)
	defer func() { _ = decapSS.Delete() }()

	_, sensitiveSet := template[CkaSensitive]
	assert.False(t, sensitiveSet, "the caller's template must not be modified")

	for name, ss := range map[string]*MLKEMSharedSecret{"encapsulated": encapSS, "decapsulated": decapSS} {
		var attrs []*pkcs11.Attribute
		require.NoError(t, ctx.withSession(func(session *pkcs11Session) (err error) {
			attrs, err = session.ctx.GetAttributeValue(session.handle, ss.handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
			})
			return err
		}))
		assert.Equal(t, []byte{1}, attrs[0].Value, "%s secret CKA_SENSITIVE", name)
		assert.Equal(t, []byte{0}, attrs[1].Value, "%s secret CKA_EXTRACTABLE", name)
		_, err := ss.Bytes()
		assert.Error(t, err, "%s secret value was readable", name)
	}
}

// plantMLKEMPublicKey creates an ML-KEM public key object carrying id and label for the
// encapsulation key value, as any session on the token can, logged in or not.
func plantMLKEMPublicKey(t *testing.T, ctx *Context, id, label, value []byte, paramSet MLKEMParameterSet) pkcs11.ObjectHandle {
	t.Helper()
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_KEM),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCAPSULATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, paramSet),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, value),
	}
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	var handle pkcs11.ObjectHandle
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) (err error) {
		handle, err = session.ctx.CreateObject(session.handle, template)
		return err
	}))
	return handle
}

// mlkemPublicValue reads the encapsulation key of a key pair's public key object.
func mlkemPublicValue(t *testing.T, ctx *Context, key MLKEMKeyPair) []byte {
	t.Helper()
	var value []byte
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		value = readAttributes(session, key.(*pkcs11MLKEMKeyPair).pubKeyHandle, pkcs11.CKA_VALUE)[0]
		return nil
	}))
	require.NotEmpty(t, value)
	return value
}

// An ML-KEM public key planted with a key pair's CKA_ID and CKA_LABEL must not be paired with the
// private key: encapsulating to it would hand the shared secret to whoever planted it.
func testMLKEMFindRejectsPlantedPublicKey(t *testing.T, ctx *Context) {
	t.Helper()
	id, label := randomBytes(), randomBytes()
	key, err := ctx.GenerateMLKEMKeyPairWithLabel(id, label, MLKEM768)
	require.NoError(t, err)
	genuine := key.(*pkcs11MLKEMKeyPair)

	other, err := ctx.GenerateMLKEMKeyPair(randomBytes(), MLKEM768)
	require.NoError(t, err)
	defer func() { _ = other.Delete() }()

	planted := make([]pkcs11.ObjectHandle, 3)
	for i := range planted {
		planted[i] = plantMLKEMPublicKey(t, ctx, id, label, mlkemPublicValue(t, ctx, other), MLKEM768)
	}
	defer func() {
		for _, h := range planted {
			destroyObject(t, ctx, h)
		}
	}()

	for range 3 {
		found, err := ctx.FindMLKEMKeyPair(id, label)
		require.NoError(t, err)
		assert.Equal(t, genuine.pubKeyHandle, found.(*pkcs11MLKEMKeyPair).pubKeyHandle,
			"FindMLKEMKeyPair paired the private key with a planted public key")
	}

	// With the genuine public key gone, only planted ones are left.
	destroyObject(t, ctx, genuine.pubKeyHandle)
	defer destroyObject(t, ctx, genuine.handle)
	_, err = ctx.FindMLKEMKeyPair(id, label)
	assert.Error(t, err, "a planted public key was accepted once the genuine one was gone")
}

// A private key with a label but no CKA_ID, whose public key cannot be found by that label, must
// not be paired with some other ML-KEM public key on the token.
func testMLKEMLabelOnlyKey(t *testing.T, ctx *Context) {
	t.Helper()
	other, err := ctx.GenerateMLKEMKeyPair(randomBytes(), MLKEM768)
	require.NoError(t, err)
	defer func() { _ = other.Delete() }()

	label := randomBytes()
	public, private := NewAttributeSet(), NewAttributeSet()
	require.NoError(t, public.Set(CkaLabel, randomBytes()))
	require.NoError(t, private.Set(CkaLabel, label))
	key, err := ctx.GenerateMLKEMKeyPairWithAttributes(public, private, MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	_, err = ctx.FindMLKEMKeyPair(nil, label)
	assert.Error(t, err, "a label-only private key was paired with another key's public half")
}

// A shared secret derived as sensitive and non-extractable stays on the token;
// asking for its bytes must be an error, never a silently empty slice that a
// caller would go on to feed to a KDF as if it were the KEM result.
func testMLKEMNonExtractableSecret(t *testing.T, ctx *Context) {
	t.Helper()
	key, err := ctx.GenerateMLKEMKeyPair(randomBytes(), MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	ssTemplate := mlkemSharedSecretTemplate()
	require.NoError(t, ssTemplate.Set(pkcs11.CKA_EXTRACTABLE, false))
	require.NoError(t, ssTemplate.Set(pkcs11.CKA_SENSITIVE, true))

	_, ss, err := key.Encapsulate(ssTemplate)
	require.NoError(t, err)
	defer func() { _ = ss.Delete() }()

	raw, err := ss.Bytes()
	require.Error(t, err)
	require.Empty(t, raw)
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

// testMLKEMEncapsulatorBytesInterop checks that the exported public-key bytes
// can be used by Go's ML-KEM implementation to encapsulate a secret that the
// token can then decapsulate.
func testMLKEMEncapsulatorBytesInterop(t *testing.T, ctx *Context) {
	t.Helper()
	id := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPair(id, MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	ssTemplate := mlkemSharedSecretTemplate()

	publicKey := key.Encapsulator()

	// Export the public key and use it for local encapsulation.
	publicKeyBytes, err := publicKey.Bytes()
	require.NoError(t, err)

	localPublicKey, err := mlkem.NewEncapsulationKey768(publicKeyBytes)
	require.NoError(t, err)
	encapBytes, ciphertext := localPublicKey.Encapsulate()

	// The token must recover the same shared secret from the locally generated ciphertext.
	decapSS, err := key.Decapsulate(ciphertext, ssTemplate)
	require.NoError(t, err)
	defer func() { _ = decapSS.Delete() }()

	decapBytes, err := decapSS.Bytes()
	require.NoError(t, err)

	// Both sides must derive the same shared secret.
	assert.Equal(t, encapBytes, decapBytes, "encapsulated and decapsulated shared secrets must match")
	assert.Len(t, encapBytes, 32, "shared secret should be 32 bytes for AES-256 template")
}

// testMLKEMEncapsulatorByAESGCM checks that a secret encapsulated on the token
// matches the secret recovered by decapsulation, without reading the
// encapsulated key back from the token.
func testMLKEMEncapsulatorByAESGCM(t *testing.T, ctx *Context) {
	t.Helper()
	id := randomBytes()
	key, err := ctx.GenerateMLKEMKeyPair(id, MLKEM768)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	ssTemplate := mlkemSharedSecretTemplate()
	testBytes := randomBytes()

	publicKey := key.Encapsulator()

	// Encapsulate on the token and retain the derived key there.
	ciphertext, encapSS, err := publicKey.Encapsulate(ssTemplate)
	require.NoError(t, err)
	defer func() { _ = encapSS.Delete() }()

	// Decapsulate the ciphertext and export this key for local encryption.
	decapSS, err := key.Decapsulate(ciphertext, ssTemplate)
	require.NoError(t, err)
	defer func() { _ = decapSS.Delete() }()

	decapBytes, err := decapSS.Bytes()
	require.NoError(t, err)

	// Encrypt locally with the decapsulated key.
	block, err := aes.NewCipher(decapBytes)
	require.NoError(t, err)
	deAead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, deAead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	encryptedData := deAead.Seal([]byte{}, nonce, testBytes, nil)

	// The token-held encapsulated key must decrypt the ciphertext.
	enAead, err := encapSS.NewGCM()
	require.NoError(t, err)
	decryptedData, err := enAead.Open([]byte{}, nonce, encryptedData, nil)
	require.NoError(t, err)

	// The recovered plaintext must match the original.
	assert.Equal(t, testBytes, decryptedData, "decrypted plaintext must match the original")
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
