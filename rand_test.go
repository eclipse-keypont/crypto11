// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomReader(t *testing.T) {
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

	reader, err := ctx.NewRandomReader()
	require.NoError(t, err)

	var a [8192]byte
	for _, size := range []int{1, 16, 32, 256, 347, 4096, 8192} {
		n, err := reader.Read(a[:size])
		require.NoError(t, err)
		require.Equal(t, size, n)
	}
}
