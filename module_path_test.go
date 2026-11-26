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
