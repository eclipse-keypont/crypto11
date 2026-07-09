// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestKeysPersistAcrossContexts(t *testing.T) {
	// Verify that close and re-open works.
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	id := randomBytes()
	_, err = ctx.GenerateRSAKeyPair(id, rsaSize)
	if err != nil {
		_ = ctx.Close()
		t.Fatal(err)
	}

	require.NoError(t, ctx.Close())

	ctx, err = ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	key2, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)

	testRsaSigning(t, key2, false)
	_ = key2.Delete()
	require.NoError(t, ctx.Close())
}

func getConfig(configLocation string) (ctx *Config, err error) {
	file, err := os.Open(configLocation)
	if err != nil {
		log.Printf("Could not open config file: %s", configLocation)
		return nil, err
	}
	defer func() {
		err = file.Close()
	}()

	configDecoder := json.NewDecoder(file)
	config := &Config{}
	err = configDecoder.Decode(config)
	if err != nil {
		log.Printf("Could decode config file: %s", err.Error())
		return nil, err
	}
	return config, nil
}

func TestKeyPairDelete(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

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
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

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
	config, err := loadConfigFromFile("crypto11.config.json")
	require.NoError(t, err)

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
	config, err := loadConfigFromFile("crypto11.config.json")
	require.NoError(t, err)

	randomSlot := int(rand.Uint32())

	config.TokenLabel = ""
	config.TokenSerial = ""
	config.SlotNumber = &randomSlot

	// Look up slot number for label
	_, err = Configure(config)
	require.Equal(t, errTokenNotFound, err)
}

func TestAccessSameLibraryTwice(t *testing.T) {
	ctx1, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	ctx2, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	// Close the first context, which shouldn't render the second
	// context unusable
	err = ctx1.Close()
	require.NoError(t, err)

	// Try to find a non-existent key. We are just checking that we can
	// use the underlying P11 lib.
	_, err = ctx2.FindKeys(randomBytes(), nil)
	require.NoError(t, err)

	err = ctx2.Close()
	require.NoError(t, err)

	// Check we can open this again and use it without error
	ctx3, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

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
	cfg, err := getConfig("crypto11.config.json")
	require.NoError(t, err)
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
	cfg, err := getConfig("crypto11.config.json")
	require.NoError(t, err)
	cfg.TokenLabel = "token1"

	cfgWrongPin, err := getConfig("crypto11.config.json")
	require.NoError(t, err)
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
	cfg, err := getConfig("crypto11.config.json")
	require.NoError(t, err)

	cfg.MaxSessions = 1
	_, err = Configure(cfg)
	require.Error(t, err)
}
