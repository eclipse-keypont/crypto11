// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func skipIfMechUnsupported(t *testing.T, ctx *Context, wantMech uint) {
	mechs, err := ctx.ctx.GetMechanismList(ctx.slot)
	require.NoError(t, err)

	for _, mech := range mechs {
		if mech == wantMech {
			return
		}
	}
	t.Skipf("mechanism 0x%x not supported", wantMech)
}

// randomBytes returns 32 random bytes.
func randomBytes() []byte {
	result := make([]byte, 32)
	rand.Read(result)
	return result
}

// The CK_ULONG conversions these tests used to cover now live in the pkcs11-go
// binding, along with their tests: see cryptoki.ULongToBytes / BytesToULong.

func makeIV(cipher *SymmetricCipher) ([]byte, error) {
	iv := make([]byte, cipher.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

func createKey(ctx *Context, keyLabel string, keySize int, KeyType int) (key *SecretKey, err error) {
	id := make([]byte, 16)
	rand.Read(id)
	if key, err = ctx.GenerateSecretKeyWithLabel(id, []byte(keyLabel), keySize, Ciphers[KeyType]); err != nil {
		return nil, fmt.Errorf("error generating key with label '%s': %w", keyLabel, err)
	}
	return key, nil
}

// findKeyOrCreate returns the key if found in the KMS
// Otherwise, it creates the key in the KMS
// Also returns a boolean to inform if the key was found. Returns 'false' if the key was not found
func findKeyOrCreate(ctx *Context, keyLabel string, keyTypeCreation int, keySizeCreation int) (key *SecretKey, found bool, err error) {
	if key, err = ctx.FindKey(nil, []byte(keyLabel)); key == nil {
		found = false
		key, err = createKey(ctx, keyLabel, keySizeCreation, keyTypeCreation)
	} else {
		found = true
	}
	return key, found, err
}
