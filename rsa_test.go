// Copyright 2024 Thales Group
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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// Set to 2048, as most tokens will support this. 1024 not supported by some tokens (e.g. Amazon CloudHSM).
const rsaSize = 2048

func TestNativeRSA(t *testing.T) {

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	key, err := rsa.GenerateKey(rand.Reader, rsaSize)
	require.NoError(t, err)

	err = key.Validate()
	require.NoError(t, err)

	t.Run("Sign", func(t *testing.T) { testRsaSigning(t, key, true) })
	t.Run("Encrypt", func(t *testing.T) { testRsaEncryption(t, key, true) })
}

func TestHardRSA(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	label := randomBytes()

	key, err := ctx.GenerateRSAKeyPairWithLabel(id, label, rsaSize)
	require.NoError(t, err)
	require.NotNil(t, key)
	defer func() { _ = key.Delete() }()

	var key2, key3 crypto.PrivateKey

	t.Run("Sign", func(t *testing.T) { testRsaSigning(t, key, false) })
	t.Run("Encrypt", func(t *testing.T) { testRsaEncryption(t, key, false) })
	t.Run("FindId", func(t *testing.T) {
		key2, err = ctx.FindKeyPair(id, nil)
		require.NoError(t, err)
	})
	t.Run("SignId", func(t *testing.T) {
		if key2 == nil {
			t.SkipNow()
		}
		testRsaSigning(t, key2.(*pkcs11PrivateKeyRSA), false)
	})
	t.Run("FindLabel", func(t *testing.T) {
		key3, err = ctx.FindKeyPair(nil, label)
		require.NoError(t, err)
	})
	t.Run("SignLabel", func(t *testing.T) {
		if key3 == nil {
			t.SkipNow()
		}
		testRsaSigning(t, key3.(crypto.Signer), false)
	})
	// test methods for RSA key pairs only
	t.Run("FindRSAKeyPair", func(t *testing.T) {
		key2, err = ctx.FindRSAKeyPair(id, nil)
		require.NoError(t, err)
		assert.NotNil(t, key2)
	})
	// test methods for RSA private key only
	t.Run("FindPrivateKey", func(t *testing.T) {
		key2, err = ctx.FindRSAPrivateKey(id, nil)
		require.NoError(t, err)
		assert.NotNil(t, key2)
	})
}

func testRsaSigning(t *testing.T, key crypto.Signer, native bool) {
	t.Run("SHA1", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA1) })
	t.Run("SHA224", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA224) })
	t.Run("SHA256", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA256) })
	t.Run("SHA384", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA384) })
	t.Run("SHA512", func(t *testing.T) { testRsaSigningPKCS1v15(t, key, crypto.SHA512) })
	t.Run("PSSSHA1", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA1, native) })
	t.Run("PSSSHA224", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA224, native) })
	t.Run("PSSSHA256", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA256, native) })
	t.Run("PSSSHA384", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA384, native) })
	t.Run("PSSSHA512", func(t *testing.T) { testRsaSigningPSS(t, key, crypto.SHA512, native) })
}

func testRsaSigningPKCS1v15(t *testing.T, key crypto.Signer, hashFunction crypto.Hash) {
	plaintext := []byte("sign me with PKCS#1 v1.5")
	h := hashFunction.New()
	_, err := h.Write(plaintext)
	require.NoError(t, err)
	plaintextHash := h.Sum([]byte{}) // weird API

	sig, err := key.Sign(rand.Reader, plaintextHash, hashFunction)
	require.NoError(t, err)

	rsaPubkey := key.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rsaPubkey, hashFunction, plaintextHash, sig)
	require.NoError(t, err)
}

func testRsaSigningPSS(t *testing.T, key crypto.Signer, hashFunction crypto.Hash, native bool) {

	if !native {
		skipIfMechUnsupported(t, key.(*pkcs11PrivateKeyRSA).context, pkcs11.CKM_RSA_PKCS_PSS)
	}

	plaintext := []byte("sign me with PSS")
	h := hashFunction.New()
	_, err := h.Write(plaintext)
	require.NoError(t, err)

	plaintextHash := h.Sum([]byte{}) // weird API
	pssOptions := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashFunction,
	}
	sig, err := key.Sign(rand.Reader, plaintextHash, pssOptions)
	require.NoError(t, err)

	rsaPubkey := key.Public().(*rsa.PublicKey)

	err = rsa.VerifyPSS(rsaPubkey, hashFunction, plaintextHash, sig, pssOptions)
	require.NoError(t, err)
}

func testRsaEncryption(t *testing.T, key crypto.Decrypter, native bool) {
	t.Run("PKCS1v15", func(t *testing.T) { testRsaEncryptionPKCS1v15(t, key) })
	t.Run("OAEPSHA1", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{}, native) })
	t.Run("OAEPSHA224", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{}, native) })
	t.Run("OAEPSHA256", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{}, native) })
	t.Run("OAEPSHA384", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{}, native) })
	t.Run("OAEPSHA512", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{}, native) })

	if !shouldSkipTest(skipTestOAEPLabel) {
		t.Run("OAEPSHA1Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA1, []byte{1, 2, 3, 4}, native) })
		t.Run("OAEPSHA224Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA224, []byte{5, 6, 7, 8}, native) })
		t.Run("OAEPSHA256Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA256, []byte{9}, native) })
		t.Run("OAEPSHA384Label", func(t *testing.T) {
			testRsaEncryptionOAEP(t, key, crypto.SHA384, []byte{10, 11, 12, 13, 14, 15}, native)
		})
		t.Run("OAEPSHA512Label", func(t *testing.T) { testRsaEncryptionOAEP(t, key, crypto.SHA512, []byte{16, 17, 18}, native) })
	}
}

func testRsaEncryptionPKCS1v15(t *testing.T, key crypto.Decrypter) {
	var err error
	var ciphertext, decrypted []byte

	plaintext := []byte("encrypt me with old and busted crypto")
	rsaPubkey := key.Public().(*rsa.PublicKey)
	if ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, rsaPubkey, plaintext); err != nil {
		t.Errorf("PKCS#1v1.5 Encrypt: %v", err)
		return
	}
	if decrypted, err = key.Decrypt(rand.Reader, ciphertext, nil); err != nil {
		t.Errorf("PKCS#1v1.5 Decrypt (nil options): %v", err)
		return
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("PKCS#1v1.5 Decrypt (nil options): wrong answer")
		return
	}
	options := &rsa.PKCS1v15DecryptOptions{
		SessionKeyLen: 0,
	}
	if decrypted, err = key.Decrypt(rand.Reader, ciphertext, options); err != nil {
		t.Errorf("PKCS#1v1.5 Decrypt %v", err)
		return
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("PKCS#1v1.5 Decrypt: wrong answer")
		return
	}
}

func testRsaEncryptionOAEP(t *testing.T, key crypto.Decrypter, hashFunction crypto.Hash, label []byte, native bool) {
	if !native {
		skipIfMechUnsupported(t, key.(*pkcs11PrivateKeyRSA).context, pkcs11.CKM_RSA_PKCS_OAEP)

		// Doesn't seem to be a way to query supported MGFs so we do that the hard way.
		info, err := key.(*pkcs11PrivateKeyRSA).context.ctx.GetInfo()
		require.NoError(t, err)

		if info.ManufacturerID == "SoftHSM" && (hashFunction != crypto.SHA1 || len(label) > 0) {
			t.Skipf("SoftHSM OAEP only supports SHA-1 with no label")
		}
	}

	plaintext := []byte("encrypt me with new hotness")
	h := hashFunction.New()
	rsaPubkey := key.Public().(*rsa.PublicKey)

	ciphertext, err := rsa.EncryptOAEP(h, rand.Reader, rsaPubkey, plaintext, label)
	require.NoError(t, err)

	options := &rsa.OAEPOptions{
		Hash:  hashFunction,
		Label: label,
	}
	decrypted, err := key.Decrypt(rand.Reader, ciphertext, options)
	require.NoError(t, err)

	require.Equal(t, plaintext, decrypted)
}

func TestRsaRequiredArgs(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	_, err = ctx.GenerateRSAKeyPair(nil, 2048)
	require.Error(t, err)

	val := randomBytes()

	_, err = ctx.GenerateRSAKeyPairWithLabel(nil, val, 2048)
	require.Error(t, err)

	_, err = ctx.GenerateRSAKeyPairWithLabel(val, nil, 2048)
	require.Error(t, err)
}
