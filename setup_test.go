// Copyright 2026 Thales Group
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestMain optionally bootstraps an ephemeral SoftHSMv3 token before running
// the test suite.
//
// Behaviour:
//
//   - SOFTHSM3_MODULE set — creates a temp token via the PKCS#11 API, writes a
//     "config" file, runs all tests, then cleans up.  No external tools required.
//   - SOFTHSM3_MODULE not set — falls back to the pre-existing "config" file
//     (the manual setup described in README.md).
//
// SoftHSMv3 (https://github.com/pqctoday/softhsmv3) is required for ML-KEM
// and other PKCS#11 v3.2 tests; a standard SoftHSMv2 install will self-skip
// those tests via skipIfMechUnsupported.
//
// Typical usage:
//
//	SOFTHSM3_MODULE=/usr/local/lib/softhsm/libsofthsm3.so go test ./...
//
// Override the user PIN (default "1234"):
//
//	SOFTHSM3_MODULE=... SOFTHSM3_PIN=mypin go test ./...
func TestMain(m *testing.M) {
	if mod := os.Getenv("SOFTHSM3_MODULE"); mod != "" {
		teardown := initSoftHSM3Token(mod)
		code := m.Run()
		teardown()
		os.Exit(code)
	}
	// No module supplied — rely on a pre-existing "config" file.
	os.Exit(m.Run())
}

// initSoftHSM3Token creates ephemeral SoftHSM tokens, initialises them
// entirely through the PKCS#11 API (C_InitToken / C_InitPIN), writes the
// "config" JSON file that ConfigureFromFile expects, and returns a teardown
// function that removes both the config and the temp token directory.
//
// Three tokens are created:
//   - "crypto11-test" — main token used by most tests (written to config)
//   - "token1" / "token2" — secondary tokens used by TestInvalidPinDoesntDestroyLibrary
//
// The function uses the same softhsm2.conf INI format accepted by both
// SoftHSMv2 and SoftHSMv3 (env var SOFTHSM2_CONF).
func initSoftHSM3Token(modulePath string) func() {
	const soPin = "0000"
	const mainLabel = "crypto11-test"
	const token1Label = "token1"
	const token2Label = "token2"

	userPin := os.Getenv("SOFTHSM3_PIN")
	if userPin == "" {
		userPin = "1234"
	}

	// ── Temp directory for SoftHSM token objects ──────────────────────────────
	dir, err := os.MkdirTemp("", "softhsm3-crypto11-*")
	if err != nil {
		panic("MkdirTemp: " + err.Error())
	}
	tokensDir := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokensDir, 0700); err != nil {
		panic("mkdir tokens: " + err.Error())
	}

	// softhsm2.conf format is accepted by both SoftHSMv2 and SoftHSMv3.
	// SOFTHSM2_CONF must be set before the module is loaded.
	confPath := filepath.Join(dir, "softhsm2.conf")
	confContent := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n",
		tokensDir,
	)
	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		panic("write softhsm2.conf: " + err.Error())
	}
	os.Setenv("SOFTHSM2_CONF", confPath)

	// ── Initialise all tokens via PKCS#11 ────────────────────────────────────
	// After each C_InitToken call SoftHSM makes a new uninitialized slot
	// available, so we can call GetSlotList(false) again to obtain it.
	p11 := pkcs11.New(modulePath)
	if p11 == nil {
		panic("pkcs11.New failed for " + modulePath)
	}
	p11Must(p11.Initialize(), "C_Initialize")

	// GetSlotList(false) = ALL slots; GetSlotList(true) = only initialized ones.
	// Uninitialized slots are the set difference. We must recompute each iteration
	// because InitToken changes the slot list.
	for _, label := range []string{mainLabel, token1Label, token2Label} {
		allSlots, err := p11.GetSlotList(false)
		p11Must(err, "C_GetSlotList(false) before "+label)
		initSlots, err := p11.GetSlotList(true)
		p11Must(err, "C_GetSlotList(true) before "+label)

		initSet := make(map[uint]bool, len(initSlots))
		for _, s := range initSlots {
			initSet[s] = true
		}

		var uninitSlot uint
		uninitFound := false
		for _, s := range allSlots {
			if !initSet[s] {
				uninitSlot = s
				uninitFound = true
				break
			}
		}
		if !uninitFound {
			panic("no uninitialized slot available for " + label)
		}
		p11Must(p11.InitToken(uninitSlot, soPin, label), "C_InitToken("+label+")")
	}

	// Set the user PIN on every initialized token.
	initSlots, err := p11.GetSlotList(true)
	p11Must(err, "C_GetSlotList(true)")
	for _, slot := range initSlots {
		sh, err := p11.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		p11Must(err, "C_OpenSession")
		p11Must(p11.Login(sh, pkcs11.CKU_SO, soPin), "C_Login(SO)")
		p11Must(p11.InitPIN(sh, userPin), "C_InitPIN")
		p11.Logout(sh)
		p11.CloseSession(sh)
	}

	p11.Finalize()
	p11.Destroy()

	// ── Write the crypto11 config file (pointing to the main token) ──────────
	cfg := Config{
		Path:       modulePath,
		TokenLabel: mainLabel,
		Pin:        userPin,
	}
	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		panic("json.Marshal config: " + err.Error())
	}

	// Back up any pre-existing config so we can restore it on teardown.
	var previousConfig []byte
	if data, err := os.ReadFile("config"); err == nil {
		previousConfig = data
	}

	if err := os.WriteFile("config", cfgBytes, 0600); err != nil {
		panic("write config: " + err.Error())
	}
	fmt.Printf("=== SoftHSMv3: tokens %q, %q, %q initialised on %s\n",
		mainLabel, token1Label, token2Label, modulePath)

	return func() {
		if len(previousConfig) > 0 {
			_ = os.WriteFile("config", previousConfig, 0600)
		} else {
			os.Remove("config")
		}
		os.RemoveAll(dir)
	}
}

// p11Must panics with a descriptive message if err is non-nil.
func p11Must(err error, op string) {
	if err != nil {
		panic(op + ": " + err.Error())
	}
}
