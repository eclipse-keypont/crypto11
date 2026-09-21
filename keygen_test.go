// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/dsa" //nolint:staticcheck // validating token-supplied keys for the DSA support this package still offers
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countObjectsWithID returns how many objects of any class carry id.
func countObjectsWithID(t *testing.T, ctx *Context, id []byte) int {
	t.Helper()
	var n int
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		handles, err := findKeys(session, id, nil, nil, nil)
		n = len(handles)
		return err
	}))
	return n
}

func TestDestroyKeyPairRemovesBothHalves(t *testing.T) {
	withContext(t, func(ctx *Context) {
		id := randomBytes()
		key, err := ctx.GenerateECDSAKeyPair(id, elliptic.P256())
		require.NoError(t, err)
		require.Equal(t, 2, countObjectsWithID(t, ctx, id))

		k := key.(*pkcs11PrivateKeyECDSA)
		cause := errors.New("the step after generation failed")
		err = ctx.withSession(func(session *pkcs11Session) error {
			return destroyKeyPair(session, k.pubKeyHandle, k.handle, cause)
		})
		require.ErrorIs(t, err, cause, "the original failure is what the caller sees")
		assert.Equal(t, 0, countObjectsWithID(t, ctx, id), "neither half may be left on the token")
	})
}

func TestECDSAUnexportableCurveCreatesNoObjects(t *testing.T) {
	// P-192 is in the OID table so it marshals, but has no Go curve to export
	// into. Generation used to succeed on the token and only then fail, leaving
	// both objects behind every time.
	withContext(t, func(ctx *Context) {
		id := randomBytes()
		_, err := ctx.GenerateECDSAKeyPair(id, &elliptic.CurveParams{Name: "P-192"})
		require.ErrorIs(t, err, errUnsupportedEllipticCurve)
		assert.Equal(t, 0, countObjectsWithID(t, ctx, id))
	})
}

func TestECDSATemplateCurveOverridesArgument(t *testing.T) {
	// The check compares the token's answer against the parameters actually
	// sent, so a template override is honoured rather than reported as a
	// mismatch against the argument.
	withContext(t, func(ctx *Context) {
		id := randomBytes()
		public, err := NewAttributeSetWithID(id)
		require.NoError(t, err)
		params, err := marshalEcParams(elliptic.P384())
		require.NoError(t, err)
		require.NoError(t, public.Set(CkaEcParams, params))
		// CKA_EC_PARAMS belongs on the public template only.
		private, err := NewAttributeSetWithID(id)
		require.NoError(t, err)

		key, err := ctx.GenerateECDSAKeyPairWithAttributes(public, private, elliptic.P256())
		require.NoError(t, err)
		defer func() { _ = key.Delete() }()
		assert.Equal(t, "P-384", key.Public().(interface{ Params() *elliptic.CurveParams }).Params().Name)
	})
}

func TestMLKEMTemplateParameterSetMustMatch(t *testing.T) {
	// Checked before any token interaction, so no Context is needed.
	ctx := &Context{cfg: &Config{}}
	public, err := NewAttributeSetWithID([]byte("id"))
	require.NoError(t, err)
	private := public.Copy()
	require.NoError(t, private.Set(CkaParameterSet, MLKEM512))

	_, err = ctx.GenerateMLKEMKeyPairWithAttributes(public, private, MLKEM1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts")

}

func TestMLKEMTemplateParameterSetAgreeing(t *testing.T) {
	// Agreeing values are not a conflict.
	withContext(t, func(ctx *Context) {
		public, err := NewAttributeSetWithID(randomBytes())
		require.NoError(t, err)
		private := public.Copy()
		require.NoError(t, private.Set(CkaParameterSet, MLKEM768))

		key, err := ctx.GenerateMLKEMKeyPairWithAttributes(public, private, MLKEM768)
		if err != nil {
			assert.NotContains(t, err.Error(), "conflicts")
			t.Skipf("ML-KEM not available on this token: %v", err)
		}
		defer func() { _ = key.Delete() }()
		assert.Equal(t, MLKEM768, key.ParameterSet())
	})
}

func TestValidateDSAPublicKey(t *testing.T) {
	params := dsaSizes[dsa.L1024N160]
	priv := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: *params}}
	require.NoError(t, dsa.GenerateKey(priv, rand.Reader))
	good := priv.PublicKey
	require.NoError(t, validateDSAPublicKey(&good))

	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(params.P, one)

	// The degenerate key the check exists for: with G = Y = 1, Go's dsa.Verify
	// accepts (1, 1) as a signature over any digest.
	degenerate := dsa.PublicKey{Parameters: dsa.Parameters{P: params.P, Q: params.Q, G: one}, Y: one}
	require.True(t, dsa.Verify(&degenerate, []byte("anything at all"), one, one),
		"precondition: the degenerate key really does forge")
	require.Error(t, validateDSAPublicKey(&degenerate))

	bad := func(name string, mutate func(k *dsa.PublicKey)) {
		t.Run(name, func(t *testing.T) {
			k := good
			k.Parameters = dsa.Parameters{P: new(big.Int).Set(good.P), Q: new(big.Int).Set(good.Q), G: new(big.Int).Set(good.G)}
			k.Y = new(big.Int).Set(good.Y)
			mutate(&k)
			assert.Error(t, validateDSAPublicKey(&k))
		})
	}
	bad("G=1", func(k *dsa.PublicKey) { k.G = one })
	bad("Y=1", func(k *dsa.PublicKey) { k.Y = one })
	bad("Y=0", func(k *dsa.PublicKey) { k.Y = new(big.Int) })
	bad("Y=p", func(k *dsa.PublicKey) { k.Y = new(big.Int).Set(k.P) })
	bad("G=p-1 (order 2)", func(k *dsa.PublicKey) { k.G = pMinus1 })
	bad("Y outside subgroup", func(k *dsa.PublicKey) { k.Y = big.NewInt(2) })
	bad("p not prime", func(k *dsa.PublicKey) { k.P = new(big.Int).Add(k.P, one) })
	bad("q not prime", func(k *dsa.PublicKey) { k.Q = new(big.Int).Add(k.Q, one) })
	bad("q does not divide p-1", func(k *dsa.PublicKey) { k.Q = big.NewInt(7919) })
	bad("q >= p", func(k *dsa.PublicKey) { k.Q = new(big.Int).Set(k.P) })
	bad("p huge", func(k *dsa.PublicKey) { k.P = new(big.Int).Lsh(one, maxDSAPrimeBits+1) })
}

func TestGeneratedKeysCleanedUpAfterTokenError(t *testing.T) {
	// A generation the token refuses outright must not leave anything behind
	// either; this pins the pre-existing path so the rollback work does not
	// regress it.
	withContext(t, func(ctx *Context) {
		id := randomBytes()
		public, err := NewAttributeSetWithID(id)
		require.NoError(t, err)
		private := public.Copy()
		// An attribute no token accepts on a private key template.
		require.NoError(t, private.Set(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))
		_, err = ctx.GenerateRSAKeyPairWithAttributes(public, private, rsaSize)
		require.Error(t, err)
		assert.Equal(t, 0, countObjectsWithID(t, ctx, id))
	})
}
