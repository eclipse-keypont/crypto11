// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto/cipher"
	"runtime"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

func TestHardSymmetric(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	t.Run("AES128", func(t *testing.T) { testHardSymmetric(t, ctx, pkcs11.CKK_AES, 128) })
	t.Run("AES192", func(t *testing.T) { testHardSymmetric(t, ctx, pkcs11.CKK_AES, 192) })
	t.Run("AES256", func(t *testing.T) { testHardSymmetric(t, ctx, pkcs11.CKK_AES, 256) })
	t.Run("DES3", func(t *testing.T) { testHardSymmetric(t, ctx, pkcs11.CKK_DES3, 0) })
}

func testHardSymmetric(t *testing.T, ctx *Context, keytype int, bits int) {
	for _, p := range Ciphers[keytype].GenParams {
		skipIfMechUnsupported(t, ctx, p.GenMech)
	}

	id := randomBytes()
	key, err := ctx.GenerateSecretKey(id, bits, Ciphers[keytype])
	require.NoError(t, err)
	require.NotNil(t, key)
	defer key.Delete()

	var key2 *SecretKey
	t.Run("Find", func(t *testing.T) {
		key2, err = ctx.FindKey(id, nil)
		require.NoError(t, err)
	})

	iv := make([]byte, key.Cipher.BlockSize)
	for i := range iv {
		iv[i] = 0xF0
	}

	t.Run("CBCClose", func(t *testing.T) {
		skipIfMechUnsupported(t, key2.context, key2.Cipher.CBCMech)
		enc, err := key2.NewCBCEncrypterCloser(iv)
		require.NoError(t, err)

		dec, err := key2.NewCBCDecrypterCloser(iv)
		require.NoError(t, err)

		testSymmetricMode(t, enc, dec)
		enc.Close()
		dec.Close()
	})

	t.Run("CBCNoClose", func(t *testing.T) {
		skipIfMechUnsupported(t, key2.context, key2.Cipher.CBCMech)
		enc, err := key2.NewCBCEncrypter(iv)
		require.NoError(t, err)

		dec, err := key2.NewCBCDecrypter(iv)
		require.NoError(t, err)
		testSymmetricMode(t, enc, dec)

		// See discussion at BlockModeCloser.
		runtime.GC()
	})

	if bits == 128 {
		t.Run("GCMSoft", func(t *testing.T) {
			aead, err := key2.NewGCM()
			require.NoError(t, err)
			testAEADMode(t, aead, 127, 129)
		})
		t.Run("GCMHard", func(t *testing.T) {
			aead, err := key2.NewGCM()
			require.NoError(t, err)
			skipIfMechUnsupported(t, key2.context, pkcs11.CKM_AES_GCM)
			testAEADMode(t, aead, 127, 129)
		})
		// TODO check that hard/soft is consistent!
	}
	// TODO CFB
	// TODO OFB
	// TODO CTR

}

func testSymmetricMode(t *testing.T, encrypt cipher.BlockMode, decrypt cipher.BlockMode) {
	// The functions in cipher.Block have no error returns, so they panic if they encounter
	// a problem. We catch these panics here, so the test can fail nicely
	defer func() {
		if cause := recover(); cause != nil {
			t.Fatalf("Caught panic: %q", cause)
		}
	}()

	input := make([]byte, 256)
	middle := make([]byte, 256)
	output := make([]byte, 256)
	// Set a recognizable pattern in the buffers
	for i := 0; i < 256; i++ {
		input[i] = byte(i)
		middle[i] = byte(i + 32)
		output[i] = byte(i + 64)
	}
	// Encrypt the first 128 bytes
	encrypt.CryptBlocks(middle, input[:128])
	if bytes.Equal(input[:128], middle[:128]) {
		t.Errorf("BlockMode.Encrypt: did not modify destination")
		return
	}
	for i := 0; i < 128; i++ {
		if input[i] != byte(i) {
			t.Errorf("BlockMode.Encrypt: corrupted source")
			return
		}
	}
	for i := 128; i < 256; i++ {
		if middle[i] != byte(i+32) {
			t.Errorf("BlockMode.Encrypt: corrupted destination past input size")
			return
		}
	}
	// Encrypt the rest
	encrypt.CryptBlocks(middle[128:], input[128:])
	// Decrypt in a single go
	decrypt.CryptBlocks(output, middle)
	if !bytes.Equal(input, output) {
		t.Errorf("BlockMode.Decrypt: plaintext wrong")
		return
	}
}

func testAEADMode(t *testing.T, aead cipher.AEAD, ptlen int, adlen int) {
	nonce := make([]byte, aead.NonceSize())
	plaintext := make([]byte, ptlen)
	for i := 0; i < len(plaintext); i++ {
		plaintext[i] = byte(i)
	}
	additionalData := make([]byte, adlen)
	for i := 0; i < len(additionalData); i++ {
		additionalData[i] = byte(i + 16)
	}
	ciphertext := aead.Seal([]byte{}, nonce, plaintext, additionalData)

	/*
		In some HSM configurations the IV may be generated and appended to the ciphertext + tag
		If this is the case (based on the ciphertext length), the test assumes that the IV has been appended
	*/
	if len(ciphertext) == aead.NonceSize()+len(plaintext)+aead.Overhead() {
		nonce = ciphertext[len(ciphertext)-aead.NonceSize():]
		ciphertext = ciphertext[:len(ciphertext)-aead.NonceSize()]
	}

	decrypted, err := aead.Open([]byte{}, nonce, ciphertext, additionalData)
	if err != nil {
		t.Errorf("aead.Open: %s", err)
		return
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("aead.Open: mismatch")
		return
	}
}

func BenchmarkCBC(b *testing.B) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(b, err)

	defer func() {
		require.NoError(b, ctx.Close())
	}()

	id := randomBytes()
	key, err := ctx.GenerateSecretKey(id, 128, Ciphers[pkcs11.CKK_AES])
	require.NoError(b, err)
	require.NotNil(b, key)
	defer key.Delete()

	iv := make([]byte, 16)
	plaintext := make([]byte, 65536)
	ciphertext := make([]byte, 65536)

	// No longer supported
	//b.Run("Native", func(b *testing.B) {
	//	for i := 0; i < b.N; i++ {
	//		mode := cipher.NewCBCEncrypter(key, iv)
	//		mode.CryptBlocks(ciphertext, plaintext)
	//	}
	//})

	b.Run("IdiomaticClose", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mode, err := key.NewCBCEncrypterCloser(iv)
			if err != nil {
				panic(err)
			}
			mode.CryptBlocks(ciphertext, plaintext)
			mode.Close()
		}
	})

	b.Run("Idiomatic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mode, err := key.NewCBCEncrypter(iv)
			if err != nil {
				panic(err)
			}
			mode.CryptBlocks(ciphertext, plaintext)
		}
		runtime.GC()
	})
}

func TestSymmetricRequiredArgs(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	_, err = ctx.GenerateSecretKey(nil, 128, CipherAES)
	require.Error(t, err)

	val := randomBytes()

	_, err = ctx.GenerateSecretKeyWithLabel(nil, val, 128, CipherAES)
	require.Error(t, err)

	_, err = ctx.GenerateSecretKeyWithLabel(val, nil, 128, CipherAES)
	require.Error(t, err)
}

// TODO BenchmarkGCM along the same lines as above
