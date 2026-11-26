// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConfigureRefusesRelativeModulePath checks that a relative module path is refused rather
// than resolved against the working directory, where a library planted under that name would be
// loaded, and its code run, in this process.
func TestConfigureRefusesRelativeModulePath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "libfake.so"), []byte("not a library"), 0o600))
	t.Chdir(dir)

	for _, relative := range []string{"libfake.so", "./libfake.so", filepath.Join("..", filepath.Base(dir), "libfake.so")} {
		_, err := Configure(&Config{Path: relative, TokenLabel: "any", Pin: "1234"})
		require.ErrorContains(t, err, "must be absolute", relative)
	}
}

// TestConfigFileOwnedByAnotherUserRefused checks that ConfigureFromFile refuses a config file
// owned by another user, whatever its mode: its owner can rewrite it to name another library.
func TestConfigFileOwnedByAnotherUserRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file to another user needs root")
	}
	path := filepath.Join(t.TempDir(), "crypto11.config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"Path": "/nonexistent/lib.so", "TokenLabel": "any"}`), 0o600))
	require.NoError(t, os.Chown(path, 4242, 4242))

	_, err := loadConfigFromFile(path)
	require.ErrorContains(t, err, "owned by uid 4242")

	require.NoError(t, os.Chown(path, 0, 0))
	_, err = loadConfigFromFile(path)
	require.NoError(t, err, "a file owned by root is accepted")
}
