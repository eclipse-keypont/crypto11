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
	"github.com/miekg/pkcs11"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlockMode(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, ctx.Close())
	}()

	// get or generate a new temporary key for encryption / decryption operations in the pkcs11 store
	key, found, err := findKeyOrCreate(ctx, "aes0", pkcs11.CKK_AES, 256)
	if err != nil {
		panic(err)
	}
	if ! found {
		// so it was dynamically created
		defer key.Delete()
	}

	iv, _ := makeIV(key.Cipher)

	t.Run("cbc mode", func(t *testing.T) { testCBCMode(t, key, iv) })
}

func trimSize(input []byte, blockSize int) (res []byte) {
	if len(input) % blockSize != 0 {
		multiplier := len(input) / blockSize
		res = make([]byte, (multiplier + 1)*blockSize)
		copy(res, input)
		return
	}
	return input
}

func initBlock(character byte, length int) []byte {
	dst := make([]byte, length)
	for i := 0; i < length; i++{
		dst[i] = character
	}
	return dst
}

func testCBCMode(t *testing.T, key *SecretKey, iv []byte){
	a := []byte("ping")
	b := initBlock('v', 100)
	short := trimSize(a, len(iv))
	long := trimSize(b, len(iv))

	// ENCRYPTION
	// short
	bmeShort, err := key.NewCBCEncrypterCloser(iv)
	require.NoError(t, err)
	cShort := make([]byte, len(short))
	bmeShort.CryptBlocks(cShort, short)
	bmeShort.Close()
	require.Equal(t, 0, len(cShort) % len(iv))
	require.NotContains(t, string(cShort), string(short), "ciphertext does not contain plaintext")
	// long
	bmeLong, err := key.NewCBCEncrypterCloser(iv)
	require.NoError(t, err)
	cLong := make([]byte, len(long))
	bmeLong.CryptBlocks(cLong, long)
	bmeLong.Close()
	require.Equal(t, 0, len(cLong) % len(iv))
	require.NotContains(t, string(cLong), string(long), "ciphertext does not contain plaintext")

	// DECRYPTION
	// short
	bmdShort, err := key.NewCBCDecrypterCloser(iv)
	require.NoError(t, err)
	pShort := make([]byte, len(short))
	bmdShort.CryptBlocks(pShort, cShort)
	bmdShort.Close()
	require.Equal(t, 0, len(pShort) % len(iv))
	require.Contains(t, string(pShort), string(short), "plaintext contains original text")
	// long
	pLong := make([]byte, len(long))
	bmd2, err := key.NewCBCDecrypterCloser(iv)
	bmd2.CryptBlocks(pLong, cLong)
	bmd2.Close()
	require.Equal(t, 0, len(pLong) % len(iv))
	require.Contains(t, string(pLong), string(long), "plaintext contains original text")

}


