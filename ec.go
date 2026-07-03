package crypto11

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// errUnsupportedEcdhCurve is returned when an edch curve
// unsupported by crypto11 is specified.  Note that the error behavior
// for an edch curve unsupported by the underlying PKCS#11
// implementation will be different.
var errUnsupportedEcdhCurve = errors.New("unsupported ecdh curve")

// pkcs11PrivateKeyEC contains a reference to a loaded PKCS#11 EC private key object.
type pkcs11PrivateKeyEC struct {
	pkcs11PrivateKey
}

// Ensure pkcs11PrivateKeyEC implements Signer and Deriver.
var (
	_ Signer  = (*pkcs11PrivateKeyEC)(nil)
	_ Deriver = (*pkcs11PrivateKeyEC)(nil)
)

// EcType is used to specify the intended use of an EC key pair when generating it.
type EcType struct {
	isDerive bool
	isVerify bool
	isSign   bool
}

var ECDH = &EcType{
	isDerive: true,
	isVerify: false,
	isSign:   false,
}

var ECDSA = &EcType{
	isDerive: false,
	isVerify: true,
	isSign:   true,
}

// Note: some of these are outside what crypto/elliptic currently
// knows about. So I'm making a (reasonable) assumption about what
// they will be called if they are either added or if someone
// specifies them explicitly.
//
// For public key export, the curve has to be a known one, otherwise
// you're stuffed. This is probably better fixed by adding well-known
// curves to crypto/elliptic rather than having a private copy here.
var wellKnownEcdhCurves = map[string]struct {
	oid   []byte
	curve ecdh.Curve
}{
	"P-256": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		ecdh.P256(),
	},
	"P-384": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}),
		ecdh.P384(),
	},
	"P-521": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}),
		ecdh.P521(),
	},
}

func unmarshalEcdhParams(b []byte) (ecdh.Curve, error) {
	// See if it's a well-known curve
	for _, ci := range wellKnownEcdhCurves {
		if bytes.Equal(b, ci.oid) {
			if ci.curve != nil {
				return ci.curve, nil
			}
			return nil, errUnsupportedEcdhCurve
		}
	}

	return nil, errUnsupportedEcdhCurve
}

func unmarshalEcdhPoint(b []byte, c ecdh.Curve) (*ecdh.PublicKey, error) {
	var pointBytes []byte
	extra, err := asn1.Unmarshal(b, &pointBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "elliptic curve point is invalid ASN.1")
	}

	if len(extra) > 0 {
		// We weren't expecting extra data
		return nil, errors.New("unexpected data found when parsing elliptic curve point")
	}

	return c.NewPublicKey(pointBytes)
}

// Export the public key corresponding to a private EC key.
func exportECPublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	var err error
	var attributes []*pkcs11.Attribute
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, nil),
	}
	if attributes, err = session.ctx.GetAttributeValue(session.handle, pubHandle, template); err != nil {
		return nil, err
	}

	if len(attributes) != len(template) {
		return nil, errors.Errorf("expected %d attributes but got %d", len(template), len(attributes))
	}

	params, point, isVerify := attributes[0], attributes[1], attributes[2]

	// If the key is a verify key, we assume it's an ECDSA public key. Otherwise, we assume it's an ECDH public key.
	// AWS CloudHSM can not set CKA_DERIVE on ECDH public keys, so we can't rely on that attribute to determine the key type.
	if bytesToBool(isVerify.Value) {
		var pub ecdsa.PublicKey
		if pub.Curve, err = unmarshalEcParams(params.Value); err != nil {
			return nil, err
		}
		if pub.X, pub.Y, err = unmarshalEcPoint(point.Value, pub.Curve); err != nil {
			return nil, err
		}
		return &pub, nil
	} else {
		curve, err := unmarshalEcdhParams(params.Value)
		if err != nil {
			return nil, err
		}

		return unmarshalEcdhPoint(point.Value, curve)
	}
}

// GenerateECKeyPair creates an EC key pair on the token using curve.
//
// Parameters:
//   - id sets CKA_ID and must be non-nil.
//   - curve is the named elliptic curve to generate on token (for example elliptic.P256()).
//   - typ declares intended key usage (for example [ECDH] for derive-only, [ECDSA] for sign/verify).
//
// Return value:
//   - The returned crypto.PrivateKey must be type-asserted by callers to the interface/struct they need.
//     For example, for ECDH key agreement you typically assert to [Deriver], and then assert the public
//     key to [*ecdh.PublicKey]. For ECDSA signing, you typically assert to [Signer] and then assert
//     the public key to [*ecdsa.PublicKey].
//
// Example (ECDH):
//
//	key, err := ctx.GenerateECKeyPair([]byte("test"), elliptic.P256(), ECDH)
//	if err != nil {
//		// handle error
//	}
//	deriver, ok := key.(Deriver)
//	if !ok {
//		// handle unexpected key type
//	}
//	pub, ok := key.Public().(*ecdh.PublicKey)
//	if !ok {
//		// handle unexpected public key type
//	}
func (c *Context) GenerateECKeyPair(id []byte, curve elliptic.Curve, typ *EcType) (crypto.PrivateKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateECKeyPairWithAttributes(public, private, curve, typ)
}

// GenerateECKeyPairWithLabel creates an EC key pair on the token using curve.
//
// Parameters:
//   - id sets CKA_ID and must be non-nil.
//   - label sets CKA_LABEL and must be non-nil.
//   - curve is the named elliptic curve to generate on token.
//   - typ declares intended key usage ([ECDH] or [ECDSA]).
//
// Return value:
//   - The returned crypto.PrivateKey must be type-asserted by callers to the interface/struct they need.
//     For example, for ECDH key agreement you typically assert to [Deriver], and then assert the public
//     key to [*ecdh.PublicKey]. For ECDSA signing, you typically assert to [Signer] and then assert
//     the public key to [*ecdsa.PublicKey].
func (c *Context) GenerateECKeyPairWithLabel(id, label []byte, curve elliptic.Curve, typ *EcType) (crypto.PrivateKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateECKeyPairWithAttributes(public, private, curve, typ)
}

// GenerateECKeyPairWithAttributes generates an EC key pair on the token with caller-provided
// public/private attribute sets.
//
// Parameters:
//   - public is the attribute set applied to the public key object.
//   - private is the attribute set applied to the private key object.
//   - curve is the named elliptic curve used for key generation.
//   - typ declares intended key usage ([ECDH] or [ECDSA]) and drives default usage attributes.
//
// Behavior:
//   - After this function returns, public and private contain the effective attributes applied
//     to the generated key objects.
//   - If required attributes are missing, defaults are applied.
//
// Return value:
//   - The returned crypto.PrivateKey must be type-asserted by callers to the interface/struct they need.
//     For example, for ECDH key agreement you typically assert to [Deriver], and then assert the public
//     key to [*ecdh.PublicKey]. For ECDSA signing, you typically assert to [Signer] and then assert
//     the public key to [*ecdsa.PublicKey].
//
// Example:
//
//	key, err := ctx.GenerateECKeyPairWithAttributes(publicAttrs, privateAttrs, elliptic.P256(), ECDH)
//	if err != nil {
//	// handle error
//	}
//	deriver, ok := key.(Deriver)
//	if !ok {
//	// handle unexpected key type
//	}
//	pub, ok := key.Public().(*ecdh.PublicKey)
//	if !ok {
//	// handle unexpected public key type
//	}
func (c *Context) GenerateECKeyPairWithAttributes(public, private AttributeSet, curve elliptic.Curve, typ *EcType) (crypto.PrivateKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	if typ == nil {
		return nil, errors.New("ec key type is required")
	}
	if curve == nil {
		return nil, errors.New("elliptic curve is required")
	}

	var k crypto.PrivateKey
	err := c.withSession(func(session *pkcs11Session) error {

		parameters, err := marshalEcParams(curve)
		if err != nil {
			return err
		}
		public.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, typ.isVerify),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, parameters),
		})
		private.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, typ.isSign),
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, typ.isDerive),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		})

		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(session.handle,
			mech,
			public.ToSlice(),
			private.ToSlice())
		if err != nil {
			return err
		}

		pub, err := exportECPublicKey(session, pubHandle)
		if err != nil {
			return err
		}
		k = &pkcs11PrivateKeyEC{
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

// Sign signs a message using an ECDSA key.
//
// This completes the implemention of crypto.Signer for pkcs11PrivateKeyEC.
//
// PKCS#11 expects to pick its own random data where necessary for signatures, so the rand argument is ignored.
//
// The return value is a DER-encoded byteblock.
func (key *pkcs11PrivateKeyEC) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.context.dsaGeneric(key.handle, pkcs11.CKM_ECDSA, digest)
}

// Derive derives a secret key from the given ECDH private key and a public key.
// The template is used to specify attributes for the derived key,
// and the cipher is used to specify the intended use of the derived key.
// The opts argument is used to specify parameters for the derive operation,
// such as the KDF to use and any KDF-specific parameters.
func (key *pkcs11PrivateKeyEC) Derive(template AttributeSet, cipher *SymmetricCipher, opts any) (*SecretKey, error) {
	if key.context.closed.Get() {
		return nil, errClosed
	}
	if cipher == nil {
		return nil, errors.New("symmetric cipher is required")
	}

	if len(cipher.GenParams) == 0 {
		return nil, errors.New("symmetric cipher has no key generation parameters")
	}

	if template == nil {
		template = NewAttributeSet()
	}

	var (
		mech    *pkcs11.Mechanism
		keySize int
	)

	switch o := opts.(type) {
	case *pkcs11.ECDH1DeriveParams:
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, o)
		l, err := getECDH1KeySize(o.KDF, key.Public())
		if err != nil {
			return nil, err
		}
		keySize = l
	default:
		return nil, errors.New("unsupported ECDH derive parameters")
	}

	// get the public key attributes to determine the size of the derived secret

	template.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, cipher.MAC),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, cipher.MAC),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, cipher.Encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, cipher.Encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keySize),
	})

	var deriveErr error
	for _, genMech := range cipher.GenParams {
		if err := template.Set(pkcs11.CKA_KEY_TYPE, genMech.KeyType); err != nil {
			return nil, err
		}

		var secret *SecretKey
		deriveErr = key.context.withSession(func(session *pkcs11Session) error {
			keyHandle, err := session.ctx.DeriveKey(session.handle,
				[]*pkcs11.Mechanism{mech},
				key.handle,
				template.ToSlice(),
			)
			if err != nil {
				return err
			}

			secret = &SecretKey{
				pkcs11Object: pkcs11Object{
					handle:  keyHandle,
					context: key.context,
				},
				Cipher: cipher,
			}
			return nil
		})

		if deriveErr == nil {
			return secret, nil
		}
	}

	return nil, errors.New("failed to derive ECDH secret key with any of the provided symmetric cipher generation parameters")
}

var wellKnownEcdh1KDFKeySize = map[uint]int{}

// RegisterECDH1CustomKDF allows users to register a custom KDF and key size for ECDH derive operations. '
// This is necessary for compatibility with some PKCS#11 implementations,
// such as AWS CloudHSM, that require the use of a custom KDF for ECDH derive operations.
// The key size is the length in bytes of the derived secret.
func RegisterECDH1CustomKDF(keyType uint, keySize int) error {
	if _, ok := wellKnownEcdh1KDFKeySize[keyType]; ok {
		return errors.Errorf("a key size is already registered for KDF type %d", keyType)
	}

	wellKnownEcdh1KDFKeySize[keyType] = keySize
	return nil
}

func getECDH1KeySize(KDF uint, pubKey crypto.PublicKey) (int, error) {
	if KDF == pkcs11.CKD_NULL {
		if k, ok := pubKey.(*ecdh.PublicKey); ok {
			info, ok := wellKnownCurves[fmt.Sprintf("%s", k.Curve())]
			if !ok || info.curve == nil {
				return 0, errors.New("unsupported curve for ECDH derive")
			}
			return (info.curve.Params().BitSize + 7) / 8, nil
		} else {
			return 0, errors.New("unsupported public key type for ECDH derive")
		}
	} else {
		l, ok := wellKnownEcdh1KDFKeySize[KDF]
		if !ok {
			return 0, errors.Errorf("unsupported KDF for ECDH derive: %d", KDF)
		}
		return l, nil
	}
}
