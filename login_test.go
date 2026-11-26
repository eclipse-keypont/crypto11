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

// TestWrongPINRefusedWhileLoggedIn checks that a second Context on a token this process has
// already logged in is refused when it presents a different PIN, which C_Login itself cannot
// tell, and accepted with the right one.
func TestWrongPINRefusedWhileLoggedIn(t *testing.T) {
	first := testConfig(t)
	if first.LoginNotSupported || first.Pin == "" {
		t.Skip("needs a token that is logged in with a configured PIN")
	}
	pin := first.Pin
	ctx, err := Configure(first)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })

	for name, configure := range map[string]func(*Config){
		"wrong PIN":     func(c *Config) { c.Pin = pin + "-wrong" },
		"wrong PinFunc": func(c *Config) { c.Pin = ""; c.PinFunc = func() ([]byte, error) { return []byte(pin + "-wrong"), nil } },
	} {
		cfg := testConfig(t)
		configure(cfg)
		other, err := Configure(cfg)
		if err == nil {
			_ = other.Close()
		}
		require.ErrorIs(t, err, errLoginPINMismatch, name)
	}

	again, err := Configure(testConfig(t))
	require.NoError(t, err, "the right PIN must still be accepted")
	require.NoError(t, again.Close())
}
