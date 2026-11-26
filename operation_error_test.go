// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"errors"
	"fmt"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// TestOperationErrorRetiresSessionUnlessTokenAnswered checks the classification of an operation
// error: the token's own return value leaves the decision to sessionFatal's list, while an error
// the binding produced, which may leave the operation active, retires the session.
func TestOperationErrorRetiresSessionUnlessTokenAnswered(t *testing.T) {
	require.NoError(t, operationError(nil))

	fromToken := pkcs11.Error(pkcs11.CKR_DATA_LEN_RANGE)
	require.Equal(t, error(fromToken), operationError(fromToken))
	require.False(t, sessionFatal(operationError(fromToken)))

	for _, err := range []error{
		errors.New("cryptoki: output size 67108880 exceeds limit 67108864"),
		fmt.Errorf("binding: %w", pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)),
	} {
		marked := operationError(err)
		require.ErrorIs(t, marked, errOperationAbandoned)
		require.ErrorIs(t, marked, err, "the original error is kept")
		require.True(t, sessionFatal(marked), "%v must retire the session", err)
	}
}

// TestOversizeSealDoesNotPoisonNextCaller checks that a Seal whose output the binding refuses, as
// too large, leaves no operation behind for the next caller of the only pooled session.
func TestOversizeSealDoesNotPoisonNextCaller(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates more than 64 MiB")
	}
	cfg := testConfig(t)
	cfg.MaxSessions = 2 // a single pooled session
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.Close() })
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_AES_GCM)
	key, err := ctx.GenerateSecretKey(randomBytes(), 256, CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() { _ = key.Delete() })
	aead, err := key.NewGCM()
	require.NoError(t, err)
	nonce := make([]byte, aead.NonceSize())

	seal := func(plaintext []byte) (cause any) {
		defer func() { cause = recover() }()
		aead.Seal(nil, nonce, plaintext, nil)
		return nil
	}
	require.NotNil(t, seal(make([]byte, 64<<20+16)), "the oversize Seal succeeded")
	require.Nil(t, seal([]byte("next caller")), "the next caller inherited the operation")
}
