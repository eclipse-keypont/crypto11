// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// TestLoginLostIsReported checks that once the login goes away underneath a Context, operations
// fail with errLoginLost rather than carrying on in sessions that are no longer logged in.
func TestLoginLostIsReported(t *testing.T) {
	cfg := testConfig(t)
	if cfg.LoginNotSupported || cfg.Pin == "" {
		t.Skip("needs a token that is logged in with a configured PIN")
	}
	pin := cfg.Pin      // Configure wipes it from cfg
	cfg.MaxSessions = 2 // a single pooled session, so the session each call draws is known
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })

	require.NoError(t, ctx.ctx.Logout(ctx.persistentSession))
	// Login state is shared by the whole process: restore it for the tests that follow. This runs
	// before ctx.Close, while the persistent session is still open.
	t.Cleanup(func() {
		require.NoError(t, ctx.ctx.Login(ctx.persistentSession, pkcs11.CKU_USER, []byte(pin)))
	})

	// The first call that needs the login fails on the pooled session, which is retired.
	_, err = ctx.GenerateSecretKey(randomBytes(), 128, CipherAES)
	require.Error(t, err)
	// Its replacement is checked, and found not logged in.
	_, err = ctx.GenerateSecretKey(randomBytes(), 128, CipherAES)
	require.ErrorIs(t, err, errLoginLost)
	_, err = ctx.FindKey(nil, randomBytes())
	require.ErrorIs(t, err, errLoginLost)
}

// TestTokenChangedIsReported checks that a new session is refused when the slot no longer holds
// the token the Context was configured for.
func TestTokenChangedIsReported(t *testing.T) {
	ctx := testContext(t)
	other := *ctx.token
	other.SerialNumber += "-replaced"
	ctx.token = &other

	_, err := ctx.resourcePoolFactoryFunc()
	require.ErrorIs(t, err, errTokenChanged)
}
