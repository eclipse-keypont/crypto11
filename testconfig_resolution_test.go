// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the precedence rules only. They never open a token, so
// they run on a machine with no PKCS#11 module installed.

// fakeModule creates a stand-in for a PKCS#11 shared object, so that
// resolveTestConfig's "does the module exist" check passes without one.
func fakeModule(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "libfake.so")
	require.NoError(t, os.WriteFile(path, []byte("not really a shared object"), 0600))
	return path
}

// writeTestConfigFile writes a JSON config file for the resolver to read.
func writeTestConfigFile(t *testing.T, path string, cfg map[string]any) {
	t.Helper()

	data, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

// envFunc turns a map into a getenv function, so a test never has to mutate
// the real process environment.
func envFunc(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestResolveTestConfigSkipsWithoutModule(t *testing.T) {
	cfg, err := resolveTestConfig(envFunc(nil), t.TempDir())

	require.ErrorIs(t, err, errNoModule)
	assert.Nil(t, cfg)
}

func TestResolveTestConfigDefaultsApplyBeneathTheModulePath(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)

	cfg, err := resolveTestConfig(envFunc(map[string]string{envModulePath: module}), dir)

	require.NoError(t, err)
	assert.Equal(t, module, cfg.Path)
	assert.Equal(t, "crypto11-test", cfg.TokenLabel)
	assert.Equal(t, "1234", cfg.Pin)
}

func TestResolveTestConfigReadsLocalFile(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json.local"), map[string]any{
		"Path":       module,
		"TokenLabel": "from-local-file",
		"Pin":        "local-pin",
	})

	cfg, err := resolveTestConfig(envFunc(nil), dir)

	require.NoError(t, err)
	assert.Equal(t, module, cfg.Path)
	assert.Equal(t, "from-local-file", cfg.TokenLabel)
	assert.Equal(t, "local-pin", cfg.Pin)
}

func TestResolveTestConfigPrefersLocalFileOverTrackedFile(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json"), map[string]any{
		"Path":       "/path/to/placeholder.so",
		"TokenLabel": "from-tracked-file",
	})
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json.local"), map[string]any{
		"Path":       module,
		"TokenLabel": "from-local-file",
	})

	cfg, err := resolveTestConfig(envFunc(nil), dir)

	require.NoError(t, err)
	assert.Equal(t, module, cfg.Path)
	assert.Equal(t, "from-local-file", cfg.TokenLabel)
}

func TestResolveTestConfigEnvironmentBeatsLocalFile(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json.local"), map[string]any{
		"Path":       "/path/that/does/not/exist.so",
		"TokenLabel": "from-local-file",
		"Pin":        "local-pin",
	})

	cfg, err := resolveTestConfig(envFunc(map[string]string{
		envModulePath: module,
		envTokenLabel: "from-env",
		envPin:        "env-pin",
	}), dir)

	require.NoError(t, err)
	assert.Equal(t, module, cfg.Path)
	assert.Equal(t, "from-env", cfg.TokenLabel)
	assert.Equal(t, "env-pin", cfg.Pin)
}

func TestResolveTestConfigFileFieldsSurviveWhenEnvIsPartial(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json.local"), map[string]any{
		"Path":        "/path/that/does/not/exist.so",
		"TokenLabel":  "from-local-file",
		"MaxSessions": 17,
	})

	// Only the module path is overridden; every other field keeps the value the
	// file supplied.
	cfg, err := resolveTestConfig(envFunc(map[string]string{envModulePath: module}), dir)

	require.NoError(t, err)
	assert.Equal(t, module, cfg.Path)
	assert.Equal(t, "from-local-file", cfg.TokenLabel)
	assert.Equal(t, 17, cfg.MaxSessions)
}

func TestResolveTestConfigHonoursConfigFileOverride(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	elsewhere := filepath.Join(t.TempDir(), "somewhere-else.json")
	writeTestConfigFile(t, elsewhere, map[string]any{
		"Path":       module,
		"TokenLabel": "from-override",
	})
	// A file in the search path that must be ignored in favour of the override.
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json.local"), map[string]any{
		"TokenLabel": "from-local-file",
	})

	cfg, err := resolveTestConfig(envFunc(map[string]string{envConfigFile: elsewhere}), dir)

	require.NoError(t, err)
	assert.Equal(t, "from-override", cfg.TokenLabel)
}

func TestResolveTestConfigReportsMissingConfigFileOverride(t *testing.T) {
	dir := t.TempDir()

	_, err := resolveTestConfig(envFunc(map[string]string{
		envConfigFile: filepath.Join(dir, "absent.json"),
	}), dir)

	// An explicitly requested file that is missing is an error, not a silent
	// fall-through to the defaults.
	require.Error(t, err)
	assert.NotErrorIs(t, err, errNoModule)
	assert.Contains(t, err.Error(), "could not open test config")
}

func TestResolveTestConfigReportsUnreadableModule(t *testing.T) {
	dir := t.TempDir()

	_, err := resolveTestConfig(envFunc(map[string]string{
		envModulePath: filepath.Join(dir, "absent.so"),
	}), dir)

	require.Error(t, err)
	assert.NotErrorIs(t, err, errNoModule)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, err.Error(), "is not usable")
}

// Configure accepts exactly one token selector, so each environment override
// must clear the other two.
func TestResolveTestConfigSelectorsAreMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	// A local file that supplies a label, to prove the override clears it.
	writeTestConfigFile(t, filepath.Join(dir, "crypto11.config.json.local"), map[string]any{
		"TokenLabel": "from-local-file",
	})

	t.Run("slot clears label and serial", func(t *testing.T) {
		cfg, err := resolveTestConfig(envFunc(map[string]string{
			envModulePath: module,
			envSlot:       "3",
		}), dir)

		require.NoError(t, err)
		require.NotNil(t, cfg.SlotNumber)
		assert.Equal(t, 3, *cfg.SlotNumber)
		assert.Empty(t, cfg.TokenLabel)
		assert.Empty(t, cfg.TokenSerial)
	})

	t.Run("serial clears label and slot", func(t *testing.T) {
		cfg, err := resolveTestConfig(envFunc(map[string]string{
			envModulePath:  module,
			envTokenSerial: "0xdeadbeef",
		}), dir)

		require.NoError(t, err)
		assert.Equal(t, "0xdeadbeef", cfg.TokenSerial)
		assert.Empty(t, cfg.TokenLabel)
		assert.Nil(t, cfg.SlotNumber)
	})

	t.Run("label clears serial and slot", func(t *testing.T) {
		cfg, err := resolveTestConfig(envFunc(map[string]string{
			envModulePath: module,
			envTokenLabel: "from-env",
		}), dir)

		require.NoError(t, err)
		assert.Equal(t, "from-env", cfg.TokenLabel)
		assert.Empty(t, cfg.TokenSerial)
		assert.Nil(t, cfg.SlotNumber)
	})
}

func TestResolveTestConfigRejectsNonNumericSlot(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)

	_, err := resolveTestConfig(envFunc(map[string]string{
		envModulePath: module,
		envSlot:       "not-a-number",
	}), dir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a slot number")
}

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	t.Setenv("CRYPTO11_TEST_EXPAND_DIR", "/opt/hsm")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty stays empty", in: "", want: ""},
		{name: "absolute path is untouched", in: "/usr/lib/libsofthsm2.so", want: "/usr/lib/libsofthsm2.so"},
		{name: "tilde expands to home", in: "~/lib/libsofthsm2.so", want: filepath.Join(home, "lib/libsofthsm2.so")},
		{name: "bare tilde expands to home", in: "~", want: home},
		{name: "variable expands", in: "$CRYPTO11_TEST_EXPAND_DIR/lib.so", want: "/opt/hsm/lib.so"},
		{name: "tilde only leading", in: "/opt/~/lib.so", want: "/opt/~/lib.so"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, expandPath(test.in))
		})
	}
}

// provisioningWanted gates a destructive C_InitToken call, so its parsing is
// worth pinning down.
func TestProvisioningWanted(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "", want: true},
		{value: "0", want: false},
		{value: "false", want: false},
		{value: "FALSE", want: false},
		{value: "no", want: false},
		{value: "off", want: false},
		{value: "  0  ", want: false},
		{value: "1", want: true},
		{value: "true", want: true},
		// Anything unrecognised keeps the turnkey SoftHSM behaviour rather than
		// silently skipping provisioning and failing every test.
		{value: "maybe", want: true},
	}

	for _, test := range tests {
		t.Run("value="+test.value, func(t *testing.T) {
			t.Setenv(envProvision, test.value)
			assert.Equal(t, test.want, provisioningWanted())
		})
	}
}

// A relative module path stays unsupported: cryptoki.New rejects it as a
// library-injection risk, and expandPath deliberately does not make it
// absolute.
func TestResolveTestConfigRejectsRelativeModulePath(t *testing.T) {
	dir := t.TempDir()
	// A file that really exists, so the failure is about the path being
	// relative rather than about the module being missing.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "libfake.so"), []byte("x"), 0600))
	t.Chdir(dir)

	for _, relative := range []string{"libfake.so", "./libfake.so"} {
		t.Run(relative, func(t *testing.T) {
			_, err := resolveTestConfig(envFunc(map[string]string{envModulePath: relative}), dir)

			require.Error(t, err)
			assert.NotErrorIs(t, err, errNoModule)
			assert.Contains(t, err.Error(), "must be absolute")
			assert.Contains(t, err.Error(), envModulePath)
		})
	}
}

// A dotenv loader hands the value over without shell expansion, so "$HOME/..."
// arrives with the $ intact. It must still resolve to an absolute path.
func TestResolveTestConfigExpandsUnexpandedVariable(t *testing.T) {
	dir := t.TempDir()
	module := fakeModule(t, dir)
	t.Setenv("CRYPTO11_TEST_MODULE_DIR", dir)

	cfg, err := resolveTestConfig(envFunc(map[string]string{
		envModulePath: "$CRYPTO11_TEST_MODULE_DIR/libfake.so",
	}), dir)

	require.NoError(t, err)
	assert.Equal(t, module, cfg.Path)
	assert.True(t, filepath.IsAbs(cfg.Path), "expansion must yield an absolute path")
}
