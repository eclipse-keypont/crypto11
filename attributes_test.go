// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/hex"
	"fmt"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetNoPanicOnWrongType(t *testing.T) {
	a := NewAttributeSet()
	err := a.Set(CkaId, []string{"this is not allowed"})
	assert.Error(t, err)
}

func TestNewAttributeNoPanicOnWrongType(t *testing.T) {
	_, err := NewAttribute(CkaId, []string{"this is not allowed"})
	assert.Error(t, err)
}

func TestAttributeSetStringRedactsKeyMaterial(t *testing.T) {
	secret := []byte("this-is-the-secret-key-material!")
	a := NewAttributeSet()
	require.NoError(t, a.Set(CkaId, []byte("public-id")))
	require.NoError(t, a.Set(CkaLabel, []byte("my label")))
	require.NoError(t, a.Set(CkaValue, secret))
	require.NoError(t, a.Set(CkaPrivateExponent, secret))
	require.NoError(t, a.Set(CkaPrime1, secret))
	require.NoError(t, a.Set(CkaPrime2, secret))
	require.NoError(t, a.Set(CkaExponent1, secret))
	require.NoError(t, a.Set(CkaExponent2, secret))
	require.NoError(t, a.Set(CkaCoefficient, secret))
	require.NoError(t, a.Set(pkcs11.CKA_VENDOR_DEFINED+1, secret))

	for _, rendered := range []string{a.String(), fmt.Sprintf("%v", a), fmt.Sprint(a)} {
		assert.NotContains(t, rendered, hex.EncodeToString(secret), "secret must not appear in hex")
		assert.NotContains(t, rendered, string(secret), "secret must not appear raw")
		assert.Contains(t, rendered, hex.EncodeToString([]byte("public-id")), "non-sensitive attributes still render")
		assert.Contains(t, rendered, "CkaValue: <redacted, 32 bytes>")
	}

	assert.False(t, sensitiveAttribute(CkaId))
	assert.False(t, sensitiveAttribute(CkaModulus), "the public modulus is not a secret")
	assert.True(t, sensitiveAttribute(CkaValue))
	assert.True(t, sensitiveAttribute(pkcs11.CKA_VENDOR_DEFINED))
}
