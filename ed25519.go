// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

var errUnsupportedEdDSAOptions = errors.New("unsupported Ed25519 signing options: only pure Ed25519 is supported")

// pkcs11-go v1.1.1 hands C_Sign a NULL pointer for an empty message; SoftHSM2
// rejects that and leaves the operation active, poisoning the session.
var errEmptyMessage = errors.New("ed25519: signing an empty message is not supported")

type pkcs11PrivateKeyEd25519 struct {
	pkcs11PrivateKey
}

// CKA_EC_PARAMS for Ed25519, in both encodings PKCS#11 v3.0 allows.
var (
	ed25519OID       = mustMarshal(asn1.ObjectIdentifier{1, 3, 101, 112})
	ed25519CurveName = mustMarshal("edwards25519")
)

func isEd25519Params(b []byte) bool {
	return bytes.Equal(b, ed25519OID) || bytes.Equal(b, ed25519CurveName)
}

// unmarshalEd25519Point accepts CKA_EC_POINT as a DER OCTET STRING or as the
// bare 32-byte point. Length decides: a bare point may start with a valid tag.
func unmarshalEd25519Point(b []byte) (ed25519.PublicKey, error) {
	switch len(b) {
	case ed25519.PublicKeySize:
	case ed25519.PublicKeySize + 2:
		if b[0] != 0x04 || b[1] != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key OCTET STRING header")
		}
		b = b[2:]
	default:
		return nil, fmt.Errorf("invalid Ed25519 public key encoding length: %d", len(b))
	}
	return bytes.Clone(b), nil
}

// Ed448 shares CKK_EC_EDWARDS; only the private key's own CKA_EC_PARAMS tells them apart.
func checkEd25519PrivateKey(session *pkcs11Session, handle pkcs11.ObjectHandle) error {
	attributes, err := session.ctx.GetAttributeValue(session.handle, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return fmt.Errorf("read Edwards private key parameters: %w", err)
	}
	if !isEd25519Params(attributes[0].Value) {
		return fmt.Errorf("%w: Edwards private key with CKA_EC_PARAMS %x is not Ed25519", errUnsupportedKeyType, attributes[0].Value)
	}
	return nil
}

func exportEd25519PublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	attributes, err := session.ctx.GetAttributeValue(session.handle, pubHandle, template)
	if err != nil {
		return nil, err
	}
	if !isEd25519Params(attributes[0].Value) {
		return nil, fmt.Errorf("%w: Edwards curve key with CKA_EC_PARAMS %x is not Ed25519", errUnsupportedKeyType, attributes[0].Value)
	}
	return unmarshalEd25519Point(attributes[1].Value)
}

func (s *pkcs11PrivateKeyEd25519) KeyType() uint {
	return pkcs11.CKK_EC_EDWARDS
}

// GenerateEd25519KeyPair creates an Ed25519 key pair on the token. The id parameter is used to
// set CKA_ID and must be non-nil.
func (c *Context) GenerateEd25519KeyPair(id []byte) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	private := public.Copy()

	return c.GenerateEd25519KeyPairWithAttributes(public, private)
}

// GenerateEd25519KeyPairWithLabel creates an Ed25519 key pair on the token. The id and label
// parameters are used to set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) GenerateEd25519KeyPairWithLabel(id, label []byte) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	private := public.Copy()

	return c.GenerateEd25519KeyPairWithAttributes(public, private)
}

// GenerateEd25519KeyPairWithAttributes generates an Ed25519 key pair on the token. After this
// function returns, public and private will contain the attributes applied to the key pair. If
// required attributes are missing, they will be set to a default value.
func (c *Context) GenerateEd25519KeyPairWithAttributes(public, private AttributeSet) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
	})
	private.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, c.defaultPrivate()),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	})

	if params := public[CkaEcParams].Value; !isEd25519Params(params) {
		return nil, fmt.Errorf("%w: CKA_EC_PARAMS %x is not Ed25519", errUnsupportedEllipticCurve, params)
	}

	var k Signer
	err := c.withSession(func(session *pkcs11Session) error {
		mech := pkcs11.NewMechanism(pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(session.handle,
			mech,
			public.ToSlice(),
			private.ToSlice())
		if err != nil {
			return err
		}

		pub, err := exportEd25519PublicKey(session, pubHandle)
		if err != nil {
			return destroyKeyPair(session, pubHandle, privHandle, err)
		}
		k = &pkcs11PrivateKeyEd25519{
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

// Sign signs a message using an Ed25519 key, completing crypto.Signer for
// pkcs11PrivateKeyEd25519. As with crypto/ed25519, message is the full message
// and opts must select no hash; Ed25519ph and Ed25519ctx are refused, as is an
// empty message. The message is signed in a single-part operation. The return
// value is the raw 64-byte signature.
func (s *pkcs11PrivateKeyEd25519) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if len(message) == 0 {
		return nil, errEmptyMessage
	}
	if opts != nil {
		if hash := opts.HashFunc(); hash != crypto.Hash(0) {
			return nil, fmt.Errorf("%w: hash %v", errUnsupportedEdDSAOptions, hash)
		}
		if o, ok := opts.(*ed25519.Options); ok && o.Context != "" {
			return nil, fmt.Errorf("%w: context data", errUnsupportedEdDSAOptions)
		}
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_EDDSA, nil)
	err = s.context.withSession(func(session *pkcs11Session) error {
		if err := session.ctx.SignInit(session.handle, mech, s.handle); err != nil {
			return fmt.Errorf("initialize Ed25519 signing: %w", err)
		}
		signature, err = session.ctx.Sign(session.handle, message)
		if err != nil {
			return fmt.Errorf("sign Ed25519 message: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("token returned a %d-byte signature, want %d", len(signature), ed25519.SignatureSize)
	}
	return signature, nil
}
