// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// TestSelectTokenRefusesAmbiguousMatch checks that a label or serial number matching more than one
// token is an error, rather than a choice of whichever slot is listed first.
func TestSelectTokenRefusesAmbiguousMatch(t *testing.T) {
	slots := []pkcs11.SlotID{3, 7, 9}
	infos := []pkcs11.TokenInfo{
		{Label: "prod", SerialNumber: "A1"},
		{Label: "prod", SerialNumber: "B2"},
		{Label: "test", SerialNumber: "C3"},
	}
	slot := 9

	i, err := selectToken(slots, infos, "B2", "", nil)
	require.NoError(t, err)
	require.Equal(t, 1, i)
	i, err = selectToken(slots, infos, "", "test", nil)
	require.NoError(t, err)
	require.Equal(t, 2, i)
	i, err = selectToken(slots, infos, "", "", &slot)
	require.NoError(t, err)
	require.Equal(t, 2, i)

	_, err = selectToken(slots, infos, "", "prod", nil)
	require.ErrorIs(t, err, errAmbiguousToken)
	_, err = selectToken(slots, infos, "", "absent", nil)
	require.ErrorIs(t, err, errTokenNotFound)
	// An empty label or serial on a token never matches.
	_, err = selectToken([]pkcs11.SlotID{1}, []pkcs11.TokenInfo{{}}, "", "", nil)
	require.ErrorIs(t, err, errTokenNotFound)
}
