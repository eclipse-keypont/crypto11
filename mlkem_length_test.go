// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// TestMLKEMCiphertextLengthChecked checks that Decapsulate refuses a ciphertext of the wrong
// length for the key's parameter set before it reaches the token, so that it costs neither the
// pooled session nor the session objects on it, and that a ciphertext of the right length still
// decapsulates.
func TestMLKEMCiphertextLengthChecked(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSessions = 2 // a single pooled session, which holds the session key below
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })

	sessionKeyAttrs := NewAttributeSet()
	require.NoError(t, sessionKeyAttrs.Set(CkaId, randomBytes()))
	require.NoError(t, sessionKeyAttrs.Set(CkaToken, false))
	sessionKey, err := ctx.GenerateSecretKeyWithAttributes(sessionKeyAttrs, 256, CipherAES)
	require.NoError(t, err)

	template := NewAttributeSet()
	require.NoError(t, template.Set(CkaClass, pkcs11.CKO_SECRET_KEY))
	require.NoError(t, template.Set(CkaKeyType, pkcs11.CKK_AES))
	require.NoError(t, template.Set(CkaValueLen, 32))
	require.NoError(t, template.Set(CkaToken, false))

	for _, paramSet := range []MLKEMParameterSet{MLKEM512, MLKEM768, MLKEM1024} {
		key, err := ctx.GenerateMLKEMKeyPair(randomBytes(), paramSet)
		if err != nil {
			t.Skipf("no ML-KEM: %v", err)
		}
		defer func(k MLKEMKeyPair) { _ = k.Delete() }(key)
		size, _ := mlkemCiphertextSize(paramSet)

		ciphertext, encapSS, err := key.Encapsulate(template)
		require.NoError(t, err)
		require.Len(t, ciphertext, size)
		require.NoError(t, encapSS.Delete())

		for _, bad := range [][]byte{ciphertext[:size-1], append(ciphertext[:size:size], 0), nil} {
			_, err := key.Decapsulate(bad, template)
			require.ErrorIs(t, err, errMLKEMCiphertextLength, "parameter set %d, %d bytes", paramSet, len(bad))
		}
		decapSS, err := key.Decapsulate(ciphertext, template)
		require.NoError(t, err)
		require.NoError(t, decapSS.Delete())
	}

	got, err := ctx.FindKey(sessionKeyAttrs[CkaId].Value, nil)
	require.NoError(t, err, "the session key did not survive")
	require.Equal(t, sessionKey.handle, got.handle)
}
