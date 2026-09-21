// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// Set to 2048, as most tokens will support this. 1024 not supported by some tokens (e.g. Amazon CloudHSM).
const rsaSize = 2048

func TestNativeRSA(t *testing.T) {
	// No token needed: this exercises the software crypto/rsa implementation
	// that the pkcs11 keys are checked against, so it runs on a clean clone.
	key, err := rsa.GenerateKey(rand.Reader, rsaSize)
	require.NoError(t, err)

	err = key.Validate()
	require.NoError(t, err)

	t.Run("Sign", func(t *testing.T) { testRsaSigning(t, key, true) })
	t.Run("Encrypt", func(t *testing.T) { testRsaEncryption(t, key, true) })
}

func TestHardRSA(t *testing.T) {
	ctx := testContext(t)

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

	plaintextHash := h.Sum(nil)
	rsaPubkey := key.Public().(*rsa.PublicKey)

	saltLengths := map[string]int{
		"Auto":       rsa.PSSSaltLengthAuto,
		"EqualsHash": rsa.PSSSaltLengthEqualsHash,
	}

	for name, saltLength := range saltLengths {
		t.Run(name, func(t *testing.T) {
			pssOptions := &rsa.PSSOptions{
				SaltLength: saltLength,
				Hash:       hashFunction,
			}
			sig, err := key.Sign(rand.Reader, plaintextHash, pssOptions)
			require.NoError(t, err)

			err = rsa.VerifyPSS(rsaPubkey, hashFunction, plaintextHash, sig, pssOptions)
			require.NoError(t, err)
		})
	}
}

// TestMaxPSSSaltLength checks that rsa.PSSSaltLengthAuto resolves to the same
// salt length crypto/rsa would choose, without needing a token that supports
// CKM_RSA_PKCS_PSS.
func TestMaxPSSSaltLength(t *testing.T) {
	for _, bits := range []int{1024, 2048, 3072, 4096} {
		// Generating a 4096-bit key dominates the runtime of this test and
		// its cost varies a lot from run to run.
		if bits > 3072 && testing.Short() {
			continue
		}

		key, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)

		for _, hashFunction := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			_, _, hLen, err := hashToPKCS11(hashFunction)
			require.NoError(t, err)

			sLen, err := maxPSSSaltLength(&key.PublicKey, hLen)
			require.NoError(t, err)

			// The same expression crypto/rsa uses for PSSSaltLengthAuto.
			want := (bits-1+7)/8 - 2 - hashFunction.Size()
			require.Equal(t, uint(want), sLen)

			// A signature made with that salt must verify as Auto.
			h := hashFunction.New()
			_, err = h.Write([]byte("sign me with PSS"))
			require.NoError(t, err)
			digest := h.Sum(nil)

			sig, err := rsa.SignPSS(rand.Reader, key, hashFunction, digest, &rsa.PSSOptions{
				SaltLength: int(sLen),
				Hash:       hashFunction,
			})
			require.NoError(t, err)

			err = rsa.VerifyPSS(&key.PublicKey, hashFunction, digest, sig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       hashFunction,
			})
			require.NoError(t, err)
		}
	}

	t.Run("NonRSAPublicKey", func(t *testing.T) {
		_, err := maxPSSSaltLength(struct{}{}, 32)
		require.ErrorIs(t, err, errUnsupportedRSAOptions)
	})

	t.Run("ModulusTooSmall", func(t *testing.T) {
		pub := &rsa.PublicKey{N: big.NewInt(65537), E: 65537} // 17-bit modulus
		_, err := maxPSSSaltLength(pub, 64)
		require.ErrorIs(t, err, rsa.ErrMessageTooLong)
	})
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
	ctx := testContext(t)

	_, err := ctx.GenerateRSAKeyPair(nil, 2048)
	require.Error(t, err)

	val := randomBytes()

	_, err = ctx.GenerateRSAKeyPairWithLabel(nil, val, 2048)
	require.Error(t, err)

	_, err = ctx.GenerateRSAKeyPairWithLabel(val, nil, 2048)
	require.Error(t, err)
}

func TestPKCS1v15SigningRejectsUnknownHashAndWrongDigest(t *testing.T) {
	withContext(t, func(ctx *Context) {
		key, err := ctx.GenerateRSAKeyPair(randomBytes(), rsaSize)
		require.NoError(t, err)
		defer func() { _ = key.Delete() }()

		digest := sha256.Sum256([]byte("message"))

		// A hash with no DigestInfo in the table used to be signed bare — as a
		// raw signature masquerading as a SHA3-256 one.
		_, err = key.Sign(rand.Reader, digest[:], crypto.SHA3_256)
		require.ErrorIs(t, err, errUnsupportedRSAOptions)

		// The digest has to be the size the named hash produces.
		_, err = key.Sign(rand.Reader, digest[:20], crypto.SHA256)
		require.Error(t, err)

		// crypto.Hash(0) is the documented way to ask for the input to be
		// signed as it is, and still works.
		sig, err := key.Sign(rand.Reader, digest[:], crypto.Hash(0))
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), crypto.Hash(0), digest[:], sig))

		// And so does the ordinary case.
		sig, err = key.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig))
	})
}

func TestPKCS1v15DecryptionFailureIsOpaque(t *testing.T) {
	withContext(t, func(ctx *Context) {
		key, err := ctx.GenerateRSAKeyPair(randomBytes(), rsaSize)
		require.NoError(t, err)
		defer func() { _ = key.Delete() }()

		pub := key.Public().(*rsa.PublicKey)
		// Random bytes below the modulus: a well-formed RSA input whose
		// decryption will not carry PKCS#1 v1.5 padding.
		garbage := make([]byte, pub.Size())
		_, err = rand.Read(garbage)
		require.NoError(t, err)
		garbage[0] = 0

		// Two acceptable outcomes. A token that reports the bad padding must
		// have its reason collapsed to rsa.ErrDecryption. A token built on a
		// library with implicit rejection (OpenSSL 3.2+, which SoftHSMv3 uses)
		// reports no error at all and returns deterministic pseudo-random
		// bytes instead, which is the stronger countermeasure; nothing to
		// collapse there.
		for _, opts := range []crypto.DecrypterOpts{nil, &rsa.PKCS1v15DecryptOptions{}} {
			out, err := key.Decrypt(rand.Reader, garbage, opts)
			if err == nil {
				t.Log("token implements implicit rejection: no error, synthetic plaintext")
				require.NotEmpty(t, out)
				continue
			}
			require.ErrorIs(t, err, rsa.ErrDecryption, "the token's reason must not be exposed")
		}

		// A real ciphertext still decrypts.
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte("hello"))
		require.NoError(t, err)
		plaintext, err := key.Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), plaintext)
	})
}

func TestOAEPMGFHashIsHonoured(t *testing.T) {
	withContext(t, func(ctx *Context) {
		skipIfMechUnsupported(t, ctx, pkcs11.CKM_RSA_PKCS_OAEP)

		key, err := ctx.GenerateRSAKeyPair(randomBytes(), rsaSize)
		require.NoError(t, err)
		defer func() { _ = key.Delete() }()
		pub := key.Public().(*rsa.PublicKey)

		// crypto/rsa encrypts with one hash for both OAEP and MGF1.
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("hello"), nil)
		require.NoError(t, err)

		// Explicitly matching MGF hash: decrypts.
		plaintext, err := key.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
		if err != nil {
			t.Skipf("token does not support OAEP with SHA-256: %v", err)
		}
		require.Equal(t, []byte("hello"), plaintext)

		// A different MGF hash used to be ignored, and this decrypted anyway.
		_, err = key.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA512})
		require.Error(t, err, "decrypting under MGF1-SHA512 what was encrypted under MGF1-SHA256 must fail")
	})
}
