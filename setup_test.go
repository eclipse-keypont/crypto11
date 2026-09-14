// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// TestMain optionally bootstraps an ephemeral SoftHSMv3 token before running
// the test suite.
//
// Behaviour:
//
//   - PKCS11_MODULE set — creates a temp token via the PKCS#11 API, points the
//     suite at it, runs all tests, then cleans up. No external tools required,
//     and nothing is written into the working tree.
//   - PKCS11_MODULE not set — falls back to whatever resolveTestConfig finds:
//     a git-ignored local config file, or the PKCS11_* variables
//     (the manual setup described in README.md).
//
// Provisioning calls C_InitToken, which is destructive on a token that is not
// a throwaway. SOFTHSM2_CONF confines SoftHSM to a temp directory, but a module
// that does not honour it (CloudHSM, nShield, a TPM) would be initialised in
// place. Set CRYPTO11_PROVISION=0 to use PKCS11_MODULE as a plain module path
// and skip provisioning entirely.
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
	// expandPath here as well as inside resolveTestConfig: this route hands the
	// value straight to cryptoki.New, and a dotenv loader delivers it verbatim.
	// VS Code's go.testEnvFile reads .env as literal key=value pairs, so
	// PKCS11_MODULE=$HOME/... arrives with the $ still in it.
	if mod := expandPath(os.Getenv(envModulePath)); mod != "" && provisioningWanted() {
		// cryptoki.New rejects a relative path because the dynamic linker would
		// resolve it against LD_LIBRARY_PATH or the working directory, and a
		// PKCS#11 module is arbitrary native code that runs on load. Fail here,
		// naming the variable, rather than panicking deep inside the binding.
		if !filepath.IsAbs(mod) {
			fmt.Fprintf(os.Stderr, "crypto11: %s must be absolute, got %q\n", envModulePath, mod)
			os.Exit(1)
		}
		teardown := initSoftHSM3Token(mod)
		code := m.Run()
		teardown()
		os.Exit(code)
	}
	// No module supplied — fall back to the resolved configuration. When no
	// module can be found at all (e.g. in CI without a provisioned HSM), narrow
	// the run to the fuzz targets in fuzz_test.go rather than failing with
	// CKR_GENERAL_ERROR on every test. Those parse bytes and need no token, so
	// their seed corpora — and the fuzzing engine itself, under -fuzz — still run
	// where the rest of the suite cannot.
	//
	// Any other resolution error (a bad path, an unparseable file) is left to
	// the individual tests, so it is reported loudly instead of being silently
	// downgraded to a fuzz-only run.
	if _, err := resolveTestConfig(os.Getenv, "."); errors.Is(err, errNoModule) {
		fmt.Fprintf(os.Stderr, "crypto11: %v — running fuzz targets only, skipping HSM tests\n", err)
		limitToFuzzTargets()
		os.Exit(m.Run())
	}
	os.Exit(m.Run())
}

// provisioningWanted reports whether TestMain should create ephemeral tokens.
//
// Unset means yes, which keeps a bare PKCS11_MODULE run working as it always
// has. It is an opt-out rather than an opt-in because the common case is
// SoftHSM, where provisioning is both safe and what makes the run turnkey.
func provisioningWanted() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envProvision))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
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
// entirely through the PKCS#11 API (C_InitToken / C_InitPIN), exports the
// PKCS11_* variables that resolveTestConfig reads, and returns a teardown
// function that removes the temp token directory.
//
// It deliberately writes no file into the working tree. An earlier version
// wrote the module path and PIN into the tracked crypto11.config.json and
// restored it on teardown, which leaked an absolute path whenever the run
// ended without teardown — a panicking test, os.Exit, or Ctrl-C.
//
// Three tokens are created:
//   - "crypto11-test" — main token used by most tests
//   - "token1" / "token2" — secondary tokens used by TestInvalidPinDoesntDestroyLibrary
//
// The function uses the same softhsm2.conf INI format accepted by both
// SoftHSMv2 and SoftHSMv3 (env var SOFTHSM2_CONF).
func initSoftHSM3Token(modulePath string) func() {
	const soPin = "0000"
	const mainLabel = "crypto11-test"
	const token1Label = "token1"
	const token2Label = "token2"

	userPin := os.Getenv(envPin)
	if userPin == "" {
		userPin = defaultTestConfig().Pin
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

	// ── Point the suite at the main token, via the environment ──────────────
	// The environment is the last layer resolveTestConfig applies, so this wins
	// over any local config file without touching the working tree.
	// PKCS11_MODULE is already set by the caller; these name the token we just
	// created inside it.
	os.Setenv(envTokenLabel, mainLabel)
	os.Setenv(envPin, userPin)
	// Clear the selectors this run does not use, in case the developer's
	// environment already set one; Configure accepts exactly one.
	os.Unsetenv(envTokenSerial)
	os.Unsetenv(envSlot)
	// A CRYPTO11_CONFIG_FILE pointing at a stale file would otherwise supply
	// fields (MaxSessions, LoginNotSupported) that this ephemeral token has not
	// been provisioned for.
	os.Unsetenv(envConfigFile)

	fmt.Printf("=== SoftHSMv3: tokens %q, %q, %q initialised on %s\n",
		mainLabel, token1Label, token2Label, modulePath)

	return func() {
		os.RemoveAll(dir)
	}
}

// p11Must panics with a descriptive message if err is non-nil.
func p11Must(err error, op string) {
	if err != nil {
		panic(op + ": " + err.Error())
	}
}
