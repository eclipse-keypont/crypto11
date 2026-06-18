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
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

func TestHmac(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

	// The hash-independent subtests (Empty/MultiSum/Reset) run once, under the plain SHA256
	// case, so they exercise a mechanism most (all?) HSMs support. The _GENERAL cases are
	// skipped there (skipIfMechUnsupported) as SoftHSM has no _GENERAL variants.
	t.Run("HMACSHA1", func(t *testing.T) {
		testHmac(t, ctx, "hmac1", pkcs11.CKK_SHA_1_HMAC, pkcs11.CKM_SHA_1_HMAC, 0, 20, false)
	})
	t.Run("HMACSHA1General", func(t *testing.T) {
		testHmac(t, ctx, "hmac1", pkcs11.CKK_SHA_1_HMAC, pkcs11.CKM_SHA_1_HMAC_GENERAL, 10, 10, false)
	})
	t.Run("HMACSHA256", func(t *testing.T) {
		testHmac(t, ctx, "hmac0", pkcs11.CKK_SHA256_HMAC, pkcs11.CKM_SHA256_HMAC, 0, 32, true)
	})

}

// After a multi-part HMAC fails mid-operation, cleanup() releases the session and
// nils it out. These tests cover the resulting dead-operation guards without an HSM:
// a zero-value hmacImplementation has both session and result nil, the same state.
func TestHmacWriteAfterSessionReleased(t *testing.T) {
	hi := &hmacImplementation{}
	n, err := hi.Write([]byte("data"))
	require.Equal(t, errHmacClosed, err)
	require.Zero(t, n)
}

func TestHmacSumAfterSessionReleased(t *testing.T) {
	hi := &hmacImplementation{}
	require.PanicsWithValue(t, errHmacClosed, func() {
		hi.Sum(nil)
	})
}

func testHmac(t *testing.T, ctx *Context, keyLabel string, keytype int, mech int, length int, xlength int, full bool) {

	skipIfMechUnsupported(t, ctx, uint(mech))

	key, found, err := findKeyOrCreate(ctx, keyLabel, keytype, 256)
	require.NoError(t, err)
	require.NotNil(t, key)
	if !found {
		// so it was created
		defer key.Delete()
	}

	t.Run("Short", func(t *testing.T) {
		input := []byte("a short string")
		h1, err := key.NewHMAC(mech, length)
		require.NoError(t, err)

		n, err := h1.Write(input)
		require.NoError(t, err)
		require.Equal(t, len(input), n)

		r1 := h1.Sum([]byte{})
		h2, err := key.NewHMAC(mech, length)
		require.NoError(t, err)

		n, err = h2.Write(input)
		require.NoError(t, err)
		require.Equal(t, len(input), n)

		r2 := h2.Sum([]byte{})

		require.Equal(t, r1, r2)
		require.Len(t, r1, xlength)
	})
	if full { // Independent of hash, only do these once
		t.Run("Empty", func(t *testing.T) {
			// Must be able to MAC empty inputs without panicing
			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)
			h1.Sum([]byte{})
		})
		t.Run("MultiSum", func(t *testing.T) {
			input := []byte("a different short string")

			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)

			n, err := h1.Write(input)
			require.NoError(t, err)
			require.Equal(t, len(input), n)

			r1 := h1.Sum([]byte{})
			r2 := h1.Sum([]byte{})
			require.Equal(t, r1, r2)

			// Can't add more after Sum()
			_, err = h1.Write(input)
			require.Equal(t, errHmacClosed, err)

			// 0-length is special
			n, err = h1.Write([]byte{})
			require.NoError(t, err)
			require.Zero(t, n)
		})
		t.Run("Reset", func(t *testing.T) {

			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)

			n, err := h1.Write([]byte{1})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			r1 := h1.Sum([]byte{})
			h1.Reset()

			n, err = h1.Write([]byte{2})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			r2 := h1.Sum([]byte{})
			h1.Reset()

			n, err = h1.Write([]byte{1})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			r3 := h1.Sum([]byte{})
			require.Equal(t, r1, r3)
			require.NotEqual(t, r1, r2)
		})
		t.Run("ResetFast", func(t *testing.T) {
			// Reset() immediately after creation should be safe

			h1, err := key.NewHMAC(mech, length)
			require.NoError(t, err)
			h1.Reset()
			n, err := h1.Write([]byte{2})
			require.NoError(t, err)
			require.Equal(t, 1, n)
			h1.Sum([]byte{})
		})
	}
}
