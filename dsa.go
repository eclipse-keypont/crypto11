// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"crypto/dsa"
	"io"
	"math/big"

	"github.com/pkg/errors"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// pkcs11PrivateKeyDSA contains a reference to a loaded PKCS#11 DSA private key object.
type pkcs11PrivateKeyDSA struct {
	pkcs11PrivateKey
}

// Export the public key corresponding to a private DSA key.
func exportDSAPublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PRIME, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SUBPRIME, nil),
		pkcs11.NewAttribute(pkcs11.CKA_BASE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	exported, err := session.ctx.GetAttributeValue(session.handle, pubHandle, template)
	if err != nil {
		return nil, err
	}
	var p, q, g, y big.Int
	p.SetBytes(exported[0].Value)
	q.SetBytes(exported[1].Value)
	g.SetBytes(exported[2].Value)
	y.SetBytes(exported[3].Value)
	result := dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: &p,
			Q: &q,
			G: &g,
		},
		Y: &y,
	}
	if err := validateDSAPublicKey(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// maxDSAPrimeBits bounds the size of a token-supplied DSA modulus before any
// modular exponentiation is attempted on it. FIPS 186-4 defines L up to 3072;
// the bound is loose so that unusual but legitimate parameters still load,
// while an attribute of megabytes cannot pin the CPU.
const maxDSAPrimeBits = 8192

// validateDSAPublicKey rejects a DSA public key whose domain parameters or
// public value are degenerate. The values come from the token, and Go's
// dsa.Verify assumes it was handed valid parameters: with G = 1 and Y = 1 it
// accepts (r, s) = (1, 1) as a signature over every digest, so a token — or
// whatever wrote to it — that supplies such a key turns software verification
// into a formality. The checks are the ones FIPS 186-4 A.2 / C.3 ask a verifier
// to make: p and q prime, q | p-1, and both g and y of order q in Z_p*.
func validateDSAPublicKey(pub *dsa.PublicKey) error {
	p, q, g, y := pub.P, pub.Q, pub.G, pub.Y
	one := big.NewInt(1)

	if p.Sign() <= 0 || q.Sign() <= 0 || g.Sign() <= 0 || y.Sign() <= 0 {
		return errors.New("DSA public key from token has a zero or negative component")
	}
	if p.BitLen() > maxDSAPrimeBits {
		return errors.Errorf("DSA prime from token is %d bits; refusing more than %d", p.BitLen(), maxDSAPrimeBits)
	}
	if q.Cmp(p) >= 0 {
		return errors.New("DSA subprime from token is not smaller than the prime")
	}
	if !p.ProbablyPrime(20) || !q.ProbablyPrime(20) {
		return errors.New("DSA prime or subprime from token is not prime")
	}
	if new(big.Int).Mod(new(big.Int).Sub(p, one), q).Sign() != 0 {
		return errors.New("DSA subprime from token does not divide p-1")
	}
	if g.Cmp(one) <= 0 || g.Cmp(p) >= 0 {
		return errors.New("DSA generator from token is not in (1, p)")
	}
	if y.Cmp(one) <= 0 || y.Cmp(p) >= 0 {
		return errors.New("DSA public value from token is not in (1, p)")
	}
	if new(big.Int).Exp(g, q, p).Cmp(one) != 0 {
		return errors.New("DSA generator from token does not have order q")
	}
	if new(big.Int).Exp(y, q, p).Cmp(one) != 0 {
		return errors.New("DSA public value from token is not in the subgroup of order q")
	}
	return nil
}

func notNilBytes(obj []byte, name string) error {
	if obj == nil {
		return errors.Errorf("%s cannot be nil", name)
	}
	return nil
}

func (signer *pkcs11PrivateKeyDSA) KeyType() uint {
	return pkcs11.CKK_DSA
}

// GenerateDSAKeyPair creates a DSA key pair on the token. The id parameter is used to
// set CKA_ID and must be non-nil.
func (c *Context) GenerateDSAKeyPair(id []byte, params *dsa.Parameters) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateDSAKeyPairWithAttributes(public, private, params)
}

// GenerateDSAKeyPairWithLabel creates a DSA key pair on the token. The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) GenerateDSAKeyPairWithLabel(id, label []byte, params *dsa.Parameters) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateDSAKeyPairWithAttributes(public, private, params)
}

// GenerateDSAKeyPairWithAttributes creates a DSA key pair on the token. After this function returns, public and private
// will contain the attributes applied to the key pair. If required attributes are missing, they will be set to a
// default value.
func (c *Context) GenerateDSAKeyPairWithAttributes(public, private AttributeSet, params *dsa.Parameters) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var k Signer
	err := c.withSession(func(session *pkcs11Session) error {
		p := params.P.Bytes()
		q := params.Q.Bytes()
		g := params.G.Bytes()

		public.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME, p),
			pkcs11.NewAttribute(pkcs11.CKA_SUBPRIME, q),
			pkcs11.NewAttribute(pkcs11.CKA_BASE, g),
		})
		private.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, c.defaultPrivate()),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		})

		mech := pkcs11.NewMechanism(pkcs11.CKM_DSA_KEY_PAIR_GEN, nil)
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(session.handle,
			mech,
			public.ToSlice(),
			private.ToSlice())
		if err != nil {
			return err
		}
		pub, err := exportDSAPublicKey(session, pubHandle)
		if err != nil {
			return destroyKeyPair(session, pubHandle, privHandle, err)
		}
		// And the domain parameters must be the ones that were asked for.
		if got := pub.(*dsa.PublicKey).Parameters; got.P.Cmp(params.P) != 0 || got.Q.Cmp(params.Q) != 0 || got.G.Cmp(params.G) != 0 {
			return destroyKeyPair(session, pubHandle, privHandle,
				errors.New("token generated a DSA key under different domain parameters than requested"))
		}
		k = &pkcs11PrivateKeyDSA{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  privHandle,
					context: c,
				},
				pubKeyHandle: pubHandle,
				pubKey:       pub,
			}}
		return nil

	})
	return k, err
}

// Sign signs a message using a DSA key.
//
// This completes the implemention of crypto.Signer for pkcs11PrivateKeyDSA.
//
// PKCS#11 expects to pick its own random data for signatures, so the rand argument is ignored.
//
// The return value is a DER-encoded byteblock.
func (signer *pkcs11PrivateKeyDSA) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	return signer.context.dsaGeneric(signer.handle, pkcs11.CKM_DSA, digest)
}

//func (signer *pkcs11PrivateKeyDSA) Public() crypto.PublicKey {
//	panic("Not implemented")
//}
