// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/sha3"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLKEMDeriveKey_KnownParameterSets covers all three ML-KEM parameter sets, checking
// MLKEMDeriveKey produces a key of the expected length and is deterministic for a fixed
// (paramSet, sharedSecret) pair — the property callers rely on to derive the same key
// independently on the encapsulation and decapsulation sides.
func TestMLKEMDeriveKey_KnownParameterSets(t *testing.T) {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		paramSet MLKEMParameterSet
		wantLen  int
	}{
		{MLKEM512, 16},
		{MLKEM768, 32},
		{MLKEM1024, 32},
	}
	for _, tc := range cases {
		k1, err := MLKEMDeriveKey(tc.paramSet, sharedSecret)
		require.NoError(t, err)
		assert.Len(t, k1, tc.wantLen)

		k2, err := MLKEMDeriveKey(tc.paramSet, sharedSecret)
		require.NoError(t, err)
		assert.Equal(t, k1, k2, "KDF must be deterministic for the same inputs")
	}
}

func TestMLKEMDeriveKey_UnsupportedParameterSet(t *testing.T) {
	_, err := MLKEMDeriveKey(9999, []byte("secret"))
	assert.Error(t, err)
}

// TestMLKEMDeriveKey_DistinctParameterSets verifies domain separation: the same shared
// secret derives a different key under each parameter set's context binding.
func TestMLKEMDeriveKey_DistinctParameterSets(t *testing.T) {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")

	k768, err := MLKEMDeriveKey(MLKEM768, sharedSecret)
	require.NoError(t, err)
	k1024, err := MLKEMDeriveKey(MLKEM1024, sharedSecret)
	require.NoError(t, err)

	assert.NotEqual(t, k768, k1024)
}

// TestKMAC128_NISTSample1 is KMAC Sample #1 from NIST SP 800-185's
// KMAC_samples.pdf: K = 40..5F, X = 00010203, L = 256, S = "".
func TestKMAC128_NISTSample1(t *testing.T) {
	key, err := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	require.NoError(t, err)
	want, err := hex.DecodeString("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e")
	require.NoError(t, err)
	assert.Equal(t, want, kmac128(key, []byte{0, 1, 2, 3}, 32))
}

// TestMLKEMDeriveKey_KnownAnswers pins the derivation to the values produced
// before the key absorption was rewritten to avoid intermediate copies of the
// shared secret: any change to the KDF's output is a compatibility break for
// every key already derived with it.
func TestMLKEMDeriveKey_KnownAnswers(t *testing.T) {
	sharedSecret := []byte("0123456789abcdef0123456789abcdef")
	cases := map[MLKEMParameterSet]string{
		MLKEM512:  "703d1cede444b66ea134cb9bbd3c1e92",
		MLKEM768:  "acacf881136b85c9356995a6aca31c5831f52bdea1a33ae90aa1e33a93103ac3",
		MLKEM1024: "8f9b85176e76922d67c5aafb2536a8a3a4940825c2bad7266d5481a71476a316",
	}
	for paramSet, wantHex := range cases {
		got, err := MLKEMDeriveKey(paramSet, sharedSecret)
		require.NoError(t, err)
		assert.Equal(t, wantHex, hex.EncodeToString(got), "parameter set %d", paramSet)
	}

	key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	assert.Equal(t,
		"2ebd1622de2de44174e3477206060d7f64489a639b7545649132317609fa214f4c8ac90630fb4c757fba074b15186fe452ae71b6a1e443bf54059e090c11ae20",
		hex.EncodeToString(kmac256(key, []byte{0, 1, 2, 3}, 64)))
}

// TestAbsorbKeyMatchesBytepad checks the single-buffer encoding against the
// reference composition it replaced, for every key length that changes the
// block count at either rate, including the empty key.
func TestAbsorbKeyMatchesBytepad(t *testing.T) {
	for _, rate := range []int{168, 136} {
		for n := 0; n <= 2*rate+1; n++ {
			key := make([]byte, n)
			for i := range key {
				key[i] = byte(i*7 + 3)
			}
			want := bytepad(encodeString(key), rate)

			h1 := sha3.NewCSHAKE128([]byte("KMAC"), nil)
			absorbKey(h1, key, rate)
			h2 := sha3.NewCSHAKE128([]byte("KMAC"), nil)
			_, _ = h2.Write(want)
			got1, got2 := make([]byte, 32), make([]byte, 32)
			_, _ = h1.Read(got1)
			_, _ = h2.Read(got2)
			require.Equal(t, got2, got1, "rate %d, key length %d", rate, n)
		}
	}
}
