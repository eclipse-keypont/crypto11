// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestKeysPersistAcrossContexts(t *testing.T) {
	// Verify that close and re-open works.
	ctx := testContext(t)

	id := randomBytes()
	_, err := ctx.GenerateRSAKeyPair(id, rsaSize)
	if err != nil {
		_ = ctx.Close()
		t.Fatal(err)
	}

	require.NoError(t, ctx.Close())

	ctx = testContext(t)

	key2, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)

	testRsaSigning(t, key2, false)
	_ = key2.Delete()
	require.NoError(t, ctx.Close())
}

func TestKeyPairDelete(t *testing.T) {
	ctx := testContext(t)

	id := randomBytes()
	key, err := ctx.GenerateRSAKeyPair(id, 2048)
	require.NoError(t, err)

	// Check we can find it
	_, err = ctx.FindKeyPair(id, nil)
	require.NoError(t, err)

	err = key.Delete()
	require.NoError(t, err)

	pairs, err := ctx.FindKeyPairs(id, nil)
	require.NoError(t, err)
	require.Empty(t, pairs)
}

func TestKeyDelete(t *testing.T) {
	ctx := testContext(t)

	id := randomBytes()
	key, err := ctx.GenerateSecretKey(id, 128, CipherAES)
	require.NoError(t, err)

	// Check we can find it
	_, err = ctx.FindKey(id, nil)
	require.NoError(t, err)

	err = key.Delete()
	require.NoError(t, err)

	keys, err := ctx.FindKeys(id, nil)
	require.NoError(t, err)
	require.Empty(t, keys)
}

func TestAmbiguousTokenConfig(t *testing.T) {
	slotNum := 1
	tests := []struct {
		config *Config
		err    string
	}{
		{
			config: &Config{TokenSerial: "serial", TokenLabel: "label"},
			err:    "config must specify exactly one way to select a token: token label, token serial number given",
		},
		{
			config: &Config{TokenSerial: "serial", SlotNumber: &slotNum},
			err:    "config must specify exactly one way to select a token: slot number, token serial number given",
		},
		{
			config: &Config{SlotNumber: &slotNum, TokenLabel: "label"},
			err:    "config must specify exactly one way to select a token: slot number, token label given",
		},
		{
			config: &Config{},
			err:    "config must specify exactly one way to select a token: none given",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			_, err := Configure(test.config)
			if assert.Error(t, err) {
				assert.Equal(t, test.err, err.Error())
			}
		})
	}
}

func TestSelectBySlot(t *testing.T) {
	config := testConfig(t)

	// Look up slot number for label
	ctx, err := Configure(config)
	require.NoError(t, err)

	slotNumber := int(ctx.slot)
	t.Logf("Using slot %d", slotNumber)
	err = ctx.Close()
	require.NoError(t, err)

	slotConfig := &Config{
		SlotNumber: &slotNumber,
		Pin:        config.Pin,
		Path:       config.Path,
	}

	ctx, err = Configure(slotConfig)
	require.NoError(t, err)

	slotNumber2 := int(ctx.slot)
	err = ctx.Close()
	require.NoError(t, err)

	assert.Equal(t, slotNumber, slotNumber2)
}

func TestSelectByNonExistingSlot(t *testing.T) {
	config := testConfig(t)

	randomSlot := int(rand.Uint32())

	config.TokenLabel = ""
	config.TokenSerial = ""
	config.SlotNumber = &randomSlot

	// Look up slot number for label
	_, err := Configure(config)
	require.Equal(t, errTokenNotFound, err)
}

func TestAccessSameLibraryTwice(t *testing.T) {
	ctx1 := testContext(t)
	ctx2 := testContext(t)

	// Close the first context, which shouldn't render the second
	// context unusable
	err := ctx1.Close()
	require.NoError(t, err)

	// Try to find a non-existent key. We are just checking that we can
	// use the underlying P11 lib.
	_, err = ctx2.FindKeys(randomBytes(), nil)
	require.NoError(t, err)

	err = ctx2.Close()
	require.NoError(t, err)

	// Check we can open this again and use it without error
	ctx3 := testContext(t)

	// Try to find a non-existent key. We are just checking that we can
	// use the underlying P11 lib.
	_, err = ctx3.FindKeys(randomBytes(), nil)
	require.NoError(t, err)

	err = ctx3.Close()
	require.NoError(t, err)
}

func TestNoLogin(t *testing.T) {
	// To test that no login is respected, we attempt to perform an operation on our
	// SoftHSM HSM without logging in and check for the error.
	//
	// Note: PKCS#11 login state is per-slot. If any other context has already
	// logged into this slot, new sessions inherit the logged-in state and this
	// test cannot be run reliably. In that case we clean up and skip.
	cfg := testConfig(t)
	cfg.LoginNotSupported = true

	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()

	key, err := ctx.GenerateSecretKey(randomBytes(), 256, CipherAES)
	if key != nil {
		// The slot is already logged in from another context; clean up the
		// unexpectedly created key and skip rather than leaving it on the token.
		_ = key.Delete()
		t.Skip("slot already logged in from another context; TestNoLogin requires an unauthenticated slot")
	}
	require.Error(t, err)

	var p11Err pkcs11.Error
	ok := errors.As(err, &p11Err)
	require.True(t, ok)

	assert.Equal(t, pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN), p11Err)
}

func TestInvalidPinDoesntDestroyLibrary(t *testing.T) {
	// This test requires two separate tokens ("token1" and "token2") so that
	// each has its own independent PKCS#11 slot login state.
	// They are created automatically when PKCS11_MODULE is set (see setup_test.go).
	// In manual-setup environments without those tokens, we skip gracefully.
	cfg := testConfig(t)
	cfg.TokenLabel = "token1"

	cfgWrongPin := testConfig(t)
	cfgWrongPin.Pin = "this_should_be_wrong_pin"
	cfgWrongPin.TokenLabel = "token2"

	// Configure context with valid configuration.
	ctx1, err := Configure(cfg)
	if errors.Is(err, errTokenNotFound) {
		t.Skip("tokens 'token1'/'token2' not found; set PKCS11_MODULE to auto-provision")
	}
	require.NoError(t, err)
	defer ctx1.Close()

	// Try to configure context with invalid pin in configuration.
	_, err = Configure(cfgWrongPin)
	require.EqualError(t, err, "failed to log into long term session: pkcs11: CKR_PIN_INCORRECT")

	// Existing context should continue to work.
	_, err = ctx1.FindAllKeys()
	require.NoError(t, err)

	// Configuring new contexts should continue to work.
	ctx2, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx2.Close()
}

func TestInvalidMaxSessions(t *testing.T) {
	cfg := testConfig(t)

	cfg.MaxSessions = 1
	_, err := Configure(cfg)
	require.Error(t, err)
}

func TestEffectiveMaxSessions(t *testing.T) {
	cases := []struct {
		name       string
		configured int
		tokenMax   uint
		want       int
		wantErr    bool
	}{
		{"token reports infinite", 1024, pkcs11.CK_EFFECTIVELY_INFINITE, 1024, false},
		{"token reports unavailable", 1024, pkcs11.CK_UNAVAILABLE_INFORMATION, 1024, false},
		{"token lower than config", 1024, 10, 10, false},
		{"config lower than token", 5, 10, 5, false},
		{"exactly two", 1024, 2, 2, false},
		{"token allows one session", 1024, 1, 0, true},
		{"config of two, token of one", 2, 1, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := effectiveMaxSessions(tc.configured, tc.tokenMax)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLoginUserType(t *testing.T) {
	ut, err := loginUserType(DefaultUserType)
	require.NoError(t, err)
	assert.Equal(t, uint(pkcs11.CKU_USER), ut)

	ut, err = loginUserType(CryptoUser)
	require.NoError(t, err)
	assert.Equal(t, uint(CryptoUser), ut)

	for _, bad := range []int{0, 2, 3, 42, -1} {
		_, err = loginUserType(bad)
		assert.Error(t, err, "UserType %d must be rejected", bad)
	}
}

func TestUnsupportedUserTypeRejectedBeforeModuleLoad(t *testing.T) {
	// A bogus module path proves the user type is checked first: had Configure
	// reached openModule, the error would be about the library, not the user type.
	cfg := &Config{Path: "/nonexistent/crypto11-test.so", TokenLabel: "x", UserType: 42}
	_, err := Configure(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported UserType 42")
}

func TestInvalidPinReleasesPersistentSession(t *testing.T) {
	// Like TestInvalidPinDoesntDestroyLibrary this needs "token1" and "token2":
	// ctx1 keeps the module loaded so a failed Configure on token2 cannot rely
	// on C_Finalize to sweep up the persistent session it opened before C_Login
	// failed. It must close that session itself, or every retry leaks one.
	cfg := testConfig(t)
	cfg.TokenLabel = "token1"

	cfgWrongPin := testConfig(t)
	cfgWrongPin.Pin = "this_should_be_wrong_pin"
	cfgWrongPin.TokenLabel = "token2"

	ctx1, err := Configure(cfg)
	if errors.Is(err, errTokenNotFound) {
		t.Skip("tokens 'token1'/'token2' not found; set PKCS11_MODULE to auto-provision")
	}
	require.NoError(t, err)
	defer ctx1.Close()

	slots, err := ctx1.ctx.GetSlotList(true)
	require.NoError(t, err)
	slot, info, err := ctx1.findToken(slots, "", "token2", nil)
	require.NoError(t, err)
	before := info.RwSessionCount

	const attempts = 5
	for i := 0; i < attempts; i++ {
		_, err = Configure(cfgWrongPin)
		require.Error(t, err)
	}

	info2, err := ctx1.ctx.GetTokenInfo(slot)
	require.NoError(t, err)
	if before == pkcs11.CK_UNAVAILABLE_INFORMATION || info2.RwSessionCount == pkcs11.CK_UNAVAILABLE_INFORMATION {
		t.Log("token does not report session counts; leak check limited to 'a later Configure still works'")
	} else {
		assert.Equal(t, before, info2.RwSessionCount,
			"%d failed logins must not leave sessions open on token2", attempts)
	}

	// And the token is still usable afterwards.
	cfgGood := testConfig(t)
	cfgGood.TokenLabel = "token2"
	ctx2, err := Configure(cfgGood)
	require.NoError(t, err)
	require.NoError(t, ctx2.Close())
}

func TestModuleCloseReportsRefcountDrift(t *testing.T) {
	ctx := testContext(t)
	defer ctx.Close()

	// A moduleCtx that is not what the cache holds under its path: the old
	// code panicked here, and there is no reason a library should.
	stray := moduleCtx{Ctx: ctx.ctx.Ctx, path: "/not/the/registered/path.so"}
	require.ErrorIs(t, stray.Close(), errModuleRefCount)

	// The real reference is untouched by the failed attempt.
	_, err := ctx.FindKeys(randomBytes(), nil)
	require.NoError(t, err)
}
