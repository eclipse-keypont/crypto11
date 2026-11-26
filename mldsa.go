//go:build go1.27

package crypto11

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// errUnsupportedMLDSAParameters is returned when an ML-DSA parameter set
// unsupported by crypto11 is specified.
var errUnsupportedMLDSAParameters = errors.New("unsupported ML-DSA parameters")

// errInvalidMLDSASignerOpts is returned when the signer options are invalid.
var errInvalidMLDSASignerOpts = errors.New("invalid SignerOpts")

func getMLDSAParameters(b []byte) (mldsa.Parameters, error) {
	switch {
	case bytes.Equal(b, []byte{1, 0, 0, 0, 0, 0, 0, 0}):
		return mldsa.MLDSA44(), nil
	case bytes.Equal(b, []byte{2, 0, 0, 0, 0, 0, 0, 0}):
		return mldsa.MLDSA65(), nil
	case bytes.Equal(b, []byte{3, 0, 0, 0, 0, 0, 0, 0}):
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, errUnsupportedMLDSAParameters
	}
}

func exportMLDSAPublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attributes, err := session.ctx.GetAttributeValue(session.handle, pubHandle, template)
	if err != nil {
		return nil, err
	}

	params, err := getMLDSAParameters(attributes[0].Value)
	if err != nil {
		return nil, err
	}

	return mldsa.NewPublicKey(params, attributes[1].Value)
}

func makeMLDSAKeyPair(session *pkcs11Session, privKey *pkcs11PrivateKey, pubHandle *pkcs11.ObjectHandle, pub crypto.PublicKey) (signer Signer, err error) {
	result := &pkcs11PrivateKeyMLDSA{pkcs11PrivateKey: *privKey}
	if pubHandle != nil {
		if pub, err = exportMLDSAPublicKey(session, *pubHandle); err != nil {
			return nil, err
		}
		result.pubKeyHandle = *pubHandle
	}

	result.pubKey = pub

	return result, nil
}

func newMLDSAMechanism(opts crypto.SignerOpts, deterministic bool) (*pkcs11.Mechanism, error) {
	var (
		mechanism uint
		params    pkcs11.MechanismParams
		context   []byte
	)

	if opts == nil {
		opts = &mldsa.Options{}
	}

	switch opts.HashFunc() {
	case 0:
		mechanism = pkcs11.CKM_ML_DSA
		if opts, ok := opts.(*mldsa.Options); ok && opts != nil && opts.Context != "" {
			context = []byte(opts.Context)
		}
		if deterministic {
			params = pkcs11.NewSignAdditionalContext(pkcs11.CKH_DETERMINISTIC_REQUIRED, context)
		} else {
			params = pkcs11.NewSignAdditionalContext(pkcs11.CKH_HEDGE_PREFERRED, context)
		}
	case crypto.MLDSAMu:
		return nil, fmt.Errorf("%w: external mu not supported", errInvalidMLDSASignerOpts)
	default:
		return nil, errInvalidMLDSASignerOpts
	}

	return pkcs11.NewMechanismWithParams(mechanism, params), nil
}

// GenerateMLDSAKeyPair creates an ML-DSA key pair on the token using the parameter set params. The id parameter is
// used to set CKA_ID and must be non-nil. The supported parameter sets are ML-DSA-44, ML-DSA-65 and ML-DSA-87. The
// underlying PKCS#11 implementation may impose further restrictions.
func (c *Context) GenerateMLDSAKeyPair(id []byte, params mldsa.Parameters) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateMLDSAKeyPairWithAttributes(public, private, params)
}

// GenerateMLDSAKeyPairWithLabel creates an ML-DSA key pair on the token using the parameter set params. The id and
// label parameters are used to set CKA_ID and CKA_LABEL respectively and must be non-nil. The supported parameter sets
// are ML-DSA-44, ML-DSA-65 and ML-DSA-87. The underlying PKCS#11 implementation may impose further restrictions.
func (c *Context) GenerateMLDSAKeyPairWithLabel(id, label []byte, params mldsa.Parameters) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateMLDSAKeyPairWithAttributes(public, private, params)
}

// GenerateMLDSAKeyPairWithAttributes generates an ML-DSA key pair on the token using the parameter set params. After
// this function returns, public and private will contain the attributes applied to the key pair. If required
// attributes are missing, they will be set to a default value. If public already contains CKA_PARAMETER_SET, it must
// match params.
func (c *Context) GenerateMLDSAKeyPairWithAttributes(public, private AttributeSet, params mldsa.Parameters) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var parameterSet *pkcs11.Attribute
	switch params {
	case mldsa.MLDSA44():
		parameterSet = pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, pkcs11.CKP_ML_DSA_44)
	case mldsa.MLDSA65():
		parameterSet = pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, pkcs11.CKP_ML_DSA_65)
	case mldsa.MLDSA87():
		parameterSet = pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, pkcs11.CKP_ML_DSA_87)
	default:
		return nil, errUnsupportedMLDSAParameters
	}

	public.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		parameterSet,
	})
	private.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, c.defaultPrivate()),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	})

	p, err := getMLDSAParameters(public[pkcs11.CKA_PARAMETER_SET].Value)
	if err != nil {
		return nil, err
	}
	if p != params {
		return nil, fmt.Errorf("unexpected ML-DSA parameters: CKA_PARAMETER_SET %s is not %s", p.String(), params.String())
	}

	var k Signer
	err = c.withSession(func(session *pkcs11Session) error {
		mech := pkcs11.NewMechanism(pkcs11.CKM_ML_DSA_KEY_PAIR_GEN, nil)
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(session.handle,
			mech,
			public.ToSlice(),
			private.ToSlice())
		if err != nil {
			return err
		}

		pub, err := exportMLDSAPublicKey(session, pubHandle)
		if err != nil {
			return destroyKeyPair(session, pubHandle, privHandle, err)
		}
		if p, ok := pub.(*mldsa.PublicKey); !ok {
			return fmt.Errorf("unexpected key type: public key is %T, not mldsa.PublicKey", pub)
		} else if p.Parameters() != params {
			return fmt.Errorf("unexpected ML-DSA parameters: CKA_PARAMETER_SET %s is not %s", p.Parameters().String(), params.String())
		}

		k = &pkcs11PrivateKeyMLDSA{
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

// pkcs11PrivateKeyMLDSA contains a reference to a loaded PKCS#11 ML-DSA private
// key object.
type pkcs11PrivateKeyMLDSA struct {
	pkcs11PrivateKey
}

func (s *pkcs11PrivateKeyMLDSA) KeyType() uint {
	return pkcs11.CKK_ML_DSA
}

// Sign signs a message using an ML-DSA key, completing crypto.Signer for
// pkcs11PrivateKeyMLDSA. As with crypto/mldsa, message is the full message and
// opts must select no hash; external mu (crypto.MLDSAMu) and pre-hashed
// messages are refused. A nil opts is equivalent to an empty *mldsa.Options,
// and the context string of an *mldsa.Options is passed to the token. The
// signature is hedged, with the randomness generated by the token, so the
// io.Reader is ignored. The message, which may be empty, is signed in a
// single-part operation. The return value is the raw signature, whose size
// depends on the parameter set of the key.
func (s *pkcs11PrivateKeyMLDSA) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	mech, err := newMLDSAMechanism(opts, false)
	if err != nil {
		return nil, err
	}
	err = s.context.withSession(func(session *pkcs11Session) error {
		if err := session.ctx.SignInit(session.handle, mech, s.handle); err != nil {
			return fmt.Errorf("initialize ML-DSA signing: %w", err)
		}
		signature, err = session.ctx.Sign(session.handle, message)
		if err != nil {
			return fmt.Errorf("sign ML-DSA message: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// SignDeterministic signs a message using an ML-DSA key like Sign, but it
// requires the token to use the deterministic variant of ML-DSA, so signing the
// same message with the same key and options always produces the same
// signature. It fails if the token does not support deterministic signing.
func (s *pkcs11PrivateKeyMLDSA) SignDeterministic(message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	mech, err := newMLDSAMechanism(opts, true)
	if err != nil {
		return nil, err
	}
	err = s.context.withSession(func(session *pkcs11Session) error {
		if err := session.ctx.SignInit(session.handle, mech, s.handle); err != nil {
			return fmt.Errorf("initialize ML-DSA signing: %w", err)
		}
		signature, err = session.ctx.Sign(session.handle, message)
		if err != nil {
			return fmt.Errorf("sign ML-DSA message: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return signature, nil

}
