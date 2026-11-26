// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// TestSessionObjectsSurvivePoolSessionRetirement checks that a key generated as a session object
// (CKA_TOKEN = false) does not belong to a pooled session: retiring the pool's session, as an
// error on another caller's operation can, must not destroy it.
func TestSessionObjectsSurvivePoolSessionRetirement(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSessions = 2 // a single pooled session
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })

	secretAttrs := NewAttributeSet()
	require.NoError(t, secretAttrs.Set(CkaId, randomBytes()))
	require.NoError(t, secretAttrs.Set(CkaToken, false))
	secret, err := ctx.GenerateSecretKeyWithAttributes(secretAttrs, 256, CipherAES)
	require.NoError(t, err)

	pairID := randomBytes()
	public, err := NewAttributeSetWithID(pairID)
	require.NoError(t, err)
	require.NoError(t, public.Set(CkaToken, false))
	private := public.Copy()
	_, err = ctx.GenerateRSAKeyPairWithAttributes(public, private, rsaSize)
	require.NoError(t, err)

	// Retire the pool's only session, as sessionFatal does after a session error.
	s, err := ctx.getSession()
	require.NoError(t, err)
	require.NoError(t, s.ctx.CloseSession(s.handle))
	ctx.putSession(s, pkcs11.Error(pkcs11.CKR_SESSION_CLOSED))

	got, err := ctx.FindKey(secretAttrs[CkaId].Value, nil)
	require.NoError(t, err, "the session secret key was destroyed with the pooled session")
	require.Equal(t, secret.handle, got.handle)
	_, err = ctx.FindKeyPair(pairID, nil)
	require.NoError(t, err, "the session key pair was destroyed with the pooled session")
}
