// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// TestMain optionally bootstraps an ephemeral SoftHSMv3 token before running
// the test suite.
//
// Behaviour:
//
//   - PKCS11_MODULE set — creates a temp token via the PKCS#11 API, writes a
//     "crypto11.config.json" file, runs all tests, then cleans up.  No external tools required.
//   - PKCS11_MODULE not set — falls back to the pre-existing "crypto11.config.json" file
//     (the manual setup described in README.md).
//   - Neither set — runs the fuzz targets only (they need no token) and skips
//     the HSM suite cleanly, without failures; used in CI when no HSM module is
//     provisioned, and by the Fuzz workflow.
//
// SoftHSMv3 (https://github.com/pqctoday-org/pqctoday-hsm) is required for ML-KEM
// and other PKCS#11 v3.2 tests; a standard SoftHSMv2 install will self-skip
// those tests via skipIfMechUnsupported.
//
// Typical usage:
//
//	PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm3.so go test ./...
//
// Override the user PIN (default "1234"):
//
//	PKCS11_MODULE=... PKCS11_PIN=mypin go test ./...
func TestMain(m *testing.M) {
	if mod := os.Getenv("PKCS11_MODULE"); mod != "" {
		teardown := initSoftHSM3Token(mod)
		code := m.Run()
		teardown()
		os.Exit(code)
	}
	// No module supplied — rely on a pre-existing "crypto11.config.json" file.
	// If that file is also absent (e.g. in CI without a provisioned HSM), narrow
	// the run to the fuzz targets in fuzz_test.go rather than failing with
	// CKR_GENERAL_ERROR on every test. Those parse bytes and need no token, so
	// their seed corpora — and the fuzzing engine itself, under -fuzz — still run
	// where the rest of the suite cannot.
	if _, err := os.Stat("crypto11.config.json"); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "crypto11: no PKCS11_MODULE and no crypto11.config.json — running fuzz targets only, skipping HSM tests")
		limitToFuzzTargets()
		os.Exit(m.Run())
	}
	os.Exit(m.Run())
}

// limitToFuzzTargets restricts the run to the FuzzXxx functions, unless the caller has
// already asked for something specific with -run. The testing package registers its flags
// before TestMain is entered but does not parse them until m.Run, hence the explicit
// flag.Parse.
func limitToFuzzTargets() {
	flag.Parse()

	run := flag.Lookup("test.run")
	if run == nil || run.Value.String() != "" {
		return
	}

	if err := flag.Set("test.run", "^Fuzz"); err != nil {
		fmt.Fprintf(os.Stderr, "crypto11: could not limit the run to fuzz targets: %v\n", err)
	}
}

// initSoftHSM3Token creates ephemeral SoftHSM tokens, initialises them
// entirely through the PKCS#11 API (C_InitToken / C_InitPIN), writes the
// "crypto11.config.json" JSON file that ConfigureFromFile expects, and returns a teardown
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

	userPin := os.Getenv("PKCS11_PIN")
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
	p11, err := pkcs11.New(modulePath)
	if err != nil {
		panic("pkcs11.New failed for " + modulePath + ": " + err.Error())
	}
	p11Must(p11.Initialize(), "C_Initialize")

	// SoftHSMv3's isTokenPresent() always returns true, so GetSlotList(false)
	// and GetSlotList(true) return identical sets. We detect the uninitialized
	// slot by inspecting CKF_TOKEN_INITIALIZED in each slot's TokenInfo instead.
	// We recompute the slot list each iteration because InitToken adds a new slot.
	for _, label := range []string{mainLabel, token1Label, token2Label} {
		allSlots, err := p11.GetSlotList(false)
		p11Must(err, "C_GetSlotList(false) before "+label)

		var uninitSlot pkcs11.SlotID
		uninitFound := false
		for _, s := range allSlots {
			info, err := p11.GetTokenInfo(s)
			if err != nil {
				continue
			}
			if info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
				uninitSlot = s
				uninitFound = true
				break
			}
		}
		if !uninitFound {
			panic("no uninitialized slot available for " + label)
		}
		p11Must(p11.InitToken(uninitSlot, []byte(soPin), label), "C_InitToken("+label+")")
	}

	// Set the user PIN on every initialized token.
	allSlots, err := p11.GetSlotList(false)
	p11Must(err, "C_GetSlotList")
	for _, slot := range allSlots {
		info, err := p11.GetTokenInfo(slot)
		if err != nil || info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			continue
		}
		sh, err := p11.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		p11Must(err, "C_OpenSession")
		p11Must(p11.Login(sh, pkcs11.CKU_SO, []byte(soPin)), "C_Login(SO)")
		p11Must(p11.InitPIN(sh, []byte(userPin)), "C_InitPIN")
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
	if data, err := os.ReadFile("crypto11.config.json"); err == nil {
		previousConfig = data
	}

	if err := os.WriteFile("crypto11.config.json", cfgBytes, 0600); err != nil {
		panic("write config: " + err.Error())
	}
	fmt.Printf("=== SoftHSMv3: tokens %q, %q, %q initialised on %s\n",
		mainLabel, token1Label, token2Label, modulePath)

	return func() {
		if len(previousConfig) > 0 {
			_ = os.WriteFile("crypto11.config.json", previousConfig, 0600)
		} else {
			os.Remove("crypto11.config.json")
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
