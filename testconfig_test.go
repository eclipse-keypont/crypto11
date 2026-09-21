// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Environment variables that override the on-disk test configuration.
//
// Naming rule, which new variables should follow: PKCS11_* says which token to
// talk to — each one maps onto a Config field — while CRYPTO11_* controls how
// the test harness behaves (CRYPTO11_SKIP in skip_test.go is the other one).
const (
	envModulePath  = "PKCS11_MODULE"
	envPin         = "PKCS11_PIN"
	envTokenLabel  = "PKCS11_TOKEN_LABEL"
	envTokenSerial = "PKCS11_TOKEN_SERIAL"
	envSlot        = "PKCS11_SLOT"

	envConfigFile = "CRYPTO11_CONFIG_FILE"
	envProvision  = "CRYPTO11_PROVISION"
)

// localConfigFiles are searched, in order, when CRYPTO11_CONFIG_FILE is unset.
// The .local variant comes first so a developer's git-ignored file always wins
// over anything sitting in the working tree.
var localConfigFiles = []string{
	"crypto11.config.json.local",
	"crypto11.config.json",
}

// errNoModule reports that no PKCS#11 module could be resolved. Tests treat it
// as a skip rather than a failure, so `go test ./...` passes on a clean clone
// with no token installed.
var errNoModule = errors.New("no PKCS#11 module configured")

// defaultTestConfig is the compiled-in base layer. It deliberately carries no
// filesystem path: a path only ever arrives from a git-ignored local file or
// from the environment, never from a tracked file.
func defaultTestConfig() *Config {
	return &Config{
		TokenLabel: "crypto11-test",
		Pin:        "1234",
	}
}

// resolveTestConfig builds the test configuration from three layers, later
// winning over earlier:
//
//  1. compiled-in defaults (defaultTestConfig)
//  2. a git-ignored JSON file (CRYPTO11_CONFIG_FILE, else the first of
//     localConfigFiles that exists in dir)
//  3. PKCS11_* environment variables
//
// Environment last is what lets CI configure a run without writing anything
// into the working tree, and keeps a developer's local file from having to be
// edited to match a runner.
//
// It takes getenv and dir rather than reading the process environment and the
// working directory directly, and returns an error rather than taking a
// *testing.T, so the precedence rules can be unit-tested on a machine with no
// HSM. loadTestConfig is the thin wrapper that turns errNoModule into a skip;
// keep the two separate.
func resolveTestConfig(getenv func(string) string, dir string) (*Config, error) {
	cfg := defaultTestConfig()

	// ── Layer 2: local JSON file ─────────────────────────────────────────────
	explicit := strings.TrimSpace(getenv(envConfigFile))
	if explicit != "" {
		// An explicitly requested file that cannot be read is an error, never a
		// silent fall-through to the defaults.
		if err := decodeConfigFile(expandPath(explicit), cfg); err != nil {
			return nil, err
		}
	} else {
		for _, name := range localConfigFiles {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			if err := decodeConfigFile(path, cfg); err != nil {
				return nil, err
			}
			break
		}
	}

	// ── Layer 3: environment overrides ───────────────────────────────────────
	if v := strings.TrimSpace(getenv(envModulePath)); v != "" {
		cfg.Path = v
	}
	if v := strings.TrimSpace(getenv(envPin)); v != "" {
		cfg.Pin = v
	}

	// Configure accepts exactly one token selector, so an override supplied by
	// the environment has to clear the two it did not set. Without this, a
	// PKCS11_SLOT run inherits the default token label and Configure rejects
	// the pair with "slot number, token label given".
	switch {
	case strings.TrimSpace(getenv(envTokenLabel)) != "":
		cfg.TokenLabel = strings.TrimSpace(getenv(envTokenLabel))
		cfg.TokenSerial = ""
		cfg.SlotNumber = nil
	case strings.TrimSpace(getenv(envTokenSerial)) != "":
		cfg.TokenSerial = strings.TrimSpace(getenv(envTokenSerial))
		cfg.TokenLabel = ""
		cfg.SlotNumber = nil
	case strings.TrimSpace(getenv(envSlot)) != "":
		raw := strings.TrimSpace(getenv(envSlot))
		slot, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%s=%q is not a slot number: %w", envSlot, raw, err)
		}
		cfg.SlotNumber = &slot
		cfg.TokenLabel = ""
		cfg.TokenSerial = ""
	}

	// ── Validation ───────────────────────────────────────────────────────────
	cfg.Path = expandPath(cfg.Path)
	if cfg.Path == "" {
		return nil, errNoModule
	}
	// Relative paths stay unsupported on purpose: cryptoki.New rejects them
	// because the dynamic linker would resolve them against LD_LIBRARY_PATH or
	// the working directory, and a PKCS#11 module is arbitrary native code that
	// runs its initialisers on load. Report it here, naming the variable, rather
	// than letting it surface from inside the binding.
	if !filepath.IsAbs(cfg.Path) {
		return nil, fmt.Errorf("PKCS#11 module path must be absolute, got %q (set %s to an absolute path)", cfg.Path, envModulePath)
	}
	if _, err := os.Stat(cfg.Path); err != nil {
		return nil, fmt.Errorf("PKCS#11 module %q is not usable: %w", cfg.Path, err)
	}

	return cfg, nil
}

// decodeConfigFile layers a JSON file over cfg. Fields absent from the file
// keep the value they already had, which is what makes the layering work.
func decodeConfigFile(path string, cfg *Config) error {
	file, err := os.Open(path) // #nosec G304 -- test-only, path comes from the developer's own environment
	if err != nil {
		return fmt.Errorf("could not open test config %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	if err := json.NewDecoder(file).Decode(cfg); err != nil {
		return fmt.Errorf("could not decode test config %q: %w", path, err)
	}
	return nil
}

// expandPath expands $VARS and a leading ~ so a local config file and the
// environment can both use them. It is deliberately not a "make this path
// absolute" helper: a relative path stays relative and is rejected by the
// caller. Expansion matters because not every way of loading the environment
// performs it — a dotenv loader hands over "$HOME/..." with the $ intact.
func expandPath(path string) string {
	if path == "" {
		return ""
	}
	path = os.ExpandEnv(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}

// loadTestConfig resolves the test configuration, skipping the calling test
// when no PKCS#11 module is available. Every returned *Config is a fresh value
// that the caller may mutate freely.
func loadTestConfig(t testing.TB) *Config {
	t.Helper()

	cfg, err := resolveTestConfig(os.Getenv, ".")
	if errors.Is(err, errNoModule) {
		t.Skipf("no PKCS#11 module configured: set %s or create %s", envModulePath, localConfigFiles[0])
	}
	require.NoError(t, err)

	return cfg
}

// testConfig is loadTestConfig under the name call sites use when they intend
// to mutate the configuration before handing it to Configure.
func testConfig(t testing.TB) *Config {
	t.Helper()
	return loadTestConfig(t)
}

// testContext opens a Context from the resolved test configuration and
// registers Close with t.Cleanup. It takes a testing.TB so benchmarks can use
// it too.
//
// Context.Close is idempotent (guarded by a sync.Once) and always returns nil,
// so a test that needs to close early may still call ctx.Close() itself; the
// cleanup then does nothing.
func testContext(t testing.TB) *Context {
	t.Helper()

	ctx, err := Configure(testConfig(t))
	require.NoError(t, err)

	t.Cleanup(func() { _ = ctx.Close() })

	return ctx
}
