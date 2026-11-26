// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/require"
)

// createFaultyRSAPrivateKey stores an RSA private key, with no public key object, whose private
// exponent is right modulo p-1 but wrong modulo q-1, so the token computes a signature that is
// wrong modulo q, as a CRT fault in a token would. The exponent itself is wrong, not just its CRT
// form, because a token that re-checks a CRT result recomputes it with the private exponent. It
// returns the key's CKA_ID and the correct public key.
func createFaultyRSAPrivateKey(t *testing.T, ctx *Context) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p, q := key.Primes[0], key.Primes[1]
	one := big.NewInt(1)
	pm1, qm1 := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
	badD := new(big.Int).Add(key.D, pm1)
	id := randomBytes()

	var handle pkcs11.ObjectHandle
	require.NoError(t, ctx.withSession(func(s *pkcs11Session) error {
		handle, err = s.ctx.CreateObject(s.handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, badD.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, p.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, q.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, new(big.Int).Mod(badD, pm1).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, new(big.Int).Mod(badD, qm1).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, new(big.Int).ModInverse(q, p).Bytes()),
		})
		return err
	}))
	t.Cleanup(func() {
		_ = ctx.withSession(func(s *pkcs11Session) error { return s.ctx.DestroyObject(s.handle, handle) })
	})
	return id, &key.PublicKey
}

// TestPrivateKeyFoundAloneChecksSignatures checks that a signature from an RSA key found without
// its public half, through FindPrivateKey or FindRSAPrivateKey, is verified before it is returned,
// like one from a key pair: a wrong signature is refused.
func TestPrivateKeyFoundAloneChecksSignatures(t *testing.T) {
	ctx := testContext(t)
	id, _ := createFaultyRSAPrivateKey(t, ctx)
	digest := sha256.Sum256([]byte("message"))

	byPrivateKey, err := ctx.FindPrivateKey(id, nil)
	require.NoError(t, err)
	byRSAPrivateKey, err := ctx.FindRSAPrivateKey(id, nil)
	require.NoError(t, err)

	for name, signer := range map[string]PrivateKey{
		"FindPrivateKey":    byPrivateKey,
		"FindRSAPrivateKey": byRSAPrivateKey,
	} {
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.ErrorIs(t, err, errRSASignatureCheck, name)
		require.Nil(t, sig, name)
	}
}
