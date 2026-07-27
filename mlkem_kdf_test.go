// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
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
