package crypto11

import (
	"crypto/ecdsa"
	"encoding/asn1"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// ImportECDSAKeyPair imports an existing ECDSA key pair onto the token. The id parameter is used to
// set CKA_ID on both objects and must be non-nil. Only the named curves supported by crypto11 are
// accepted. The underlying PKCS#11 implementation may impose further restrictions (e.g. on
// importing private key material at all).
func (c *Context) ImportECDSAKeyPair(id []byte, key *ecdsa.PrivateKey) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	private := public.Copy()

	return c.ImportECDSAKeyPairWithAttributes(public, private, key)
}

// ImportECDSAKeyPairWithLabel imports an existing ECDSA key pair onto the token. The id and label
// parameters set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) ImportECDSAKeyPairWithLabel(id, label []byte, key *ecdsa.PrivateKey) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	private := public.Copy()

	return c.ImportECDSAKeyPairWithAttributes(public, private, key)
}

// ImportECDSAKeyPairWithAttributes imports an existing ECDSA key pair onto the token. After this
// function returns, public and private will contain the attributes applied to the imported objects.
// The key material (CKA_EC_PARAMS, CKA_EC_POINT, CKA_VALUE) and the object classes are always set
// from key; any other missing attributes are given default values, so callers may override
// defaults such as CKA_SENSITIVE/CKA_EXTRACTABLE by presetting them on private.
//
// The two objects are created sequentially rather than atomically. If the private key is created
// but the public key fails, the orphaned private key is destroyed before the error is returned.
func (c *Context) ImportECDSAKeyPairWithAttributes(public, private AttributeSet, key *ecdsa.PrivateKey) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}

	parameters, err := marshalEcParams(key.Curve)
	if err != nil {
		return nil, err
	}

	// Use crypto/ecdh for the byte encodings, avoiding the deprecated elliptic/big.Int APIs.
	// ECDH supports P-256/384/521 but not P-224, so a curve crypto11 can generate may not be
	// importable; the error is explicit rather than a silent gap.
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, errors.WithMessage(err, "curve not supported for import")
	}

	// CKA_EC_POINT is the uncompressed point wrapped in a DER OCTET STRING, per PKCS#11.
	// PublicKey.Bytes returns exactly that uncompressed encoding (0x04 || X || Y).
	ecPoint, err := asn1.Marshal(ecdhKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	// PrivateKey.Bytes is the fixed-length big-endian scalar, matching CKA_VALUE.
	value := ecdhKey.Bytes()

	public.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	})
	// CKA_CLASS, CKA_KEY_TYPE and the key material define the object; set them unconditionally.
	_ = public.Set(CkaClass, pkcs11.CKO_PUBLIC_KEY)
	_ = public.Set(CkaKeyType, pkcs11.CKK_ECDSA)
	_ = public.Set(CkaEcParams, parameters)
	_ = public.Set(CkaEcPoint, ecPoint)

	private.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	})
	_ = private.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
	_ = private.Set(CkaKeyType, pkcs11.CKK_ECDSA)
	_ = private.Set(CkaEcParams, parameters)
	_ = private.Set(CkaValue, value)

	var k Signer
	err = c.withSession(func(session *pkcs11Session) error {
		pubHandle, err := session.ctx.CreateObject(session.handle, public.ToSlice())
		if err != nil {
			return err
		}

		privHandle, err := session.ctx.CreateObject(session.handle, private.ToSlice())
		if err != nil {
			// Roll back the orphaned public key so a retry sees a clean token.
			_ = session.ctx.DestroyObject(session.handle, pubHandle)
			return err
		}

		k = &pkcs11PrivateKeyECDSA{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  privHandle,
					context: c,
				},
				pubKeyHandle: pubHandle,
				pubKey:       &key.PublicKey,
			}}
		return nil
	})
	return k, err
}
