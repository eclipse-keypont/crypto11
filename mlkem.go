// Copyright 2026 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package crypto11

import (
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// MLKEMParameterSet identifies an ML-KEM security level as defined in FIPS 203.
type MLKEMParameterSet = uint

// ML-KEM parameter set constants (PKCS#11 v3.2 CKP_ML_KEM_*).
const (
	MLKEM512  MLKEMParameterSet = pkcs11.CKP_ML_KEM_512
	MLKEM768  MLKEMParameterSet = pkcs11.CKP_ML_KEM_768
	MLKEM1024 MLKEMParameterSet = pkcs11.CKP_ML_KEM_1024
)

// pkcs11MLKEMKeyPair holds PKCS#11 object handles for an ML-KEM key pair.
// The embedded pkcs11Object.handle is the private key; pubKeyHandle is the public key.
type pkcs11MLKEMKeyPair struct {
	pkcs11Object
	pubKeyHandle pkcs11.ObjectHandle
	paramSet     MLKEMParameterSet
}

// MLKEMSharedSecret wraps a PKCS#11 object handle for a KEM-derived shared secret key.
// The object is created on the token by Encapsulate or Decapsulate.
type MLKEMSharedSecret struct {
	pkcs11Object
}

// Bytes extracts the raw shared secret value from the token.
// The key must have been created with CKA_EXTRACTABLE = true in the shared secret template.
func (s *MLKEMSharedSecret) Bytes() ([]byte, error) {
	var raw []byte
	err := s.context.withSession(func(session *pkcs11Session) error {
		attrs, err := session.ctx.GetAttributeValue(session.handle, s.handle,
			[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
		if err != nil {
			return err
		}
		raw = append([]byte(nil), attrs[0].Value...)
		return nil
	})
	return raw, err
}

// MLKEMEncapsulator is an ML-KEM public key capable of encapsulating a shared secret.
type MLKEMEncapsulator interface {
	// Encapsulate generates a fresh shared secret, encapsulates it with the public key, and
	// derives a new key object on the token using sharedSecretAttrs as the template.
	// The returned ciphertext must be transmitted to the holder of the matching private key.
	Encapsulate(sharedSecretAttrs AttributeSet) (ciphertext []byte, sharedSecret *MLKEMSharedSecret, err error)

	// ParameterSet returns the ML-KEM security level (MLKEM512, MLKEM768, or MLKEM1024).
	ParameterSet() MLKEMParameterSet

	// Delete removes the public key object from the token.
	Delete() error
}

// MLKEMDecapsulator is an ML-KEM private key capable of recovering a shared secret from a ciphertext.
type MLKEMDecapsulator interface {
	// Decapsulate recovers the shared secret from a ciphertext produced by the matching
	// encapsulator, deriving a new key object on the token using sharedSecretAttrs as the template.
	Decapsulate(ciphertext []byte, sharedSecretAttrs AttributeSet) (*MLKEMSharedSecret, error)

	// ParameterSet returns the ML-KEM security level (MLKEM512, MLKEM768, or MLKEM1024).
	ParameterSet() MLKEMParameterSet

	// Delete removes the private key object from the token.
	Delete() error
}

// MLKEMKeyPair is a full ML-KEM key pair supporting both encapsulation and decapsulation.
type MLKEMKeyPair interface {
	MLKEMEncapsulator
	MLKEMDecapsulator
}

// Delete destroys both the private and public key objects on the token.
func (k *pkcs11MLKEMKeyPair) Delete() error {
	if err := k.pkcs11Object.Delete(); err != nil {
		return err
	}
	return k.context.withSession(func(session *pkcs11Session) error {
		err := session.ctx.DestroyObject(session.handle, k.pubKeyHandle)
		return errors.WithMessage(err, "failed to destroy ML-KEM public key")
	})
}

// ParameterSet returns the ML-KEM security level for this key pair.
func (k *pkcs11MLKEMKeyPair) ParameterSet() MLKEMParameterSet {
	return k.paramSet
}

// Encapsulate performs ML-KEM encapsulation using the public key (PKCS#11 v3.2 C_EncapsulateKey).
// sharedSecretAttrs must describe the desired derived key (e.g. CKK_AES, CKA_VALUE_LEN = 32).
func (k *pkcs11MLKEMKeyPair) Encapsulate(sharedSecretAttrs AttributeSet) ([]byte, *MLKEMSharedSecret, error) {
	var ciphertext []byte
	var ss *MLKEMSharedSecret
	err := k.context.withSession(func(session *pkcs11Session) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_KEM, nil)}
		ct, ssHandle, err := session.ctx.EncapsulateKey(
			session.handle, mech, k.pubKeyHandle, sharedSecretAttrs.ToSlice())
		if err != nil {
			return err
		}
		ciphertext = ct
		ss = &MLKEMSharedSecret{pkcs11Object{handle: ssHandle, context: k.context}}
		return nil
	})
	return ciphertext, ss, err
}

// Decapsulate performs ML-KEM decapsulation using the private key (PKCS#11 v3.2 C_DecapsulateKey).
// sharedSecretAttrs should match the template used during encapsulation.
func (k *pkcs11MLKEMKeyPair) Decapsulate(ciphertext []byte, sharedSecretAttrs AttributeSet) (*MLKEMSharedSecret, error) {
	var ss *MLKEMSharedSecret
	err := k.context.withSession(func(session *pkcs11Session) error {
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_KEM, nil)}
		ssHandle, err := session.ctx.DecapsulateKey(
			session.handle, mech, k.handle, sharedSecretAttrs.ToSlice(), ciphertext)
		if err != nil {
			return err
		}
		ss = &MLKEMSharedSecret{pkcs11Object{handle: ssHandle, context: k.context}}
		return nil
	})
	return ss, err
}

// GenerateMLKEMKeyPair creates an ML-KEM key pair on the token. The id parameter is used to
// set CKA_ID and must be non-nil.
func (c *Context) GenerateMLKEMKeyPair(id []byte, paramSet MLKEMParameterSet) (MLKEMKeyPair, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	private := public.Copy()
	return c.GenerateMLKEMKeyPairWithAttributes(public, private, paramSet)
}

// GenerateMLKEMKeyPairWithLabel creates an ML-KEM key pair on the token. The id and label
// parameters are used to set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) GenerateMLKEMKeyPairWithLabel(id, label []byte, paramSet MLKEMParameterSet) (MLKEMKeyPair, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	private := public.Copy()
	return c.GenerateMLKEMKeyPairWithAttributes(public, private, paramSet)
}

// GenerateMLKEMKeyPairWithAttributes generates an ML-KEM key pair on the token. After this
// function returns, public and private will contain the attributes applied to the key pair.
// If required attributes are missing they will be set to a default value.
func (c *Context) GenerateMLKEMKeyPairWithAttributes(public, private AttributeSet, paramSet MLKEMParameterSet) (MLKEMKeyPair, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	var k MLKEMKeyPair
	err := c.withSession(func(session *pkcs11Session) error {
		public.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ML_KEM),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCAPSULATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, paramSet),
		})
		private.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_DECAPSULATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, paramSet),
		})
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_KEM_KEY_PAIR_GEN, nil)}
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(
			session.handle, mech, public.ToSlice(), private.ToSlice())
		if err != nil {
			return err
		}
		k = &pkcs11MLKEMKeyPair{
			pkcs11Object: pkcs11Object{handle: privHandle, context: c},
			pubKeyHandle: pubHandle,
			paramSet:     paramSet,
		}
		return nil
	})
	return k, err
}

// makeMLKEMKeyPair reconstructs an MLKEMKeyPair from a private key handle by locating
// the matching public key on the token via CKA_ID / CKA_LABEL.
func (c *Context) makeMLKEMKeyPair(session *pkcs11Session, privHandle *pkcs11.ObjectHandle) (MLKEMKeyPair, error) {
	attrs, err := session.ctx.GetAttributeValue(session.handle, *privHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PARAMETER_SET, nil),
	})
	if err != nil {
		return nil, err
	}
	id := attrs[0].Value
	label := attrs[1].Value
	paramSet := MLKEMParameterSet(bytesToUlong(attrs[2].Value))

	if len(id) == 0 && len(label) == 0 {
		return nil, errNoCkaId
	}

	keyType := uint(pkcs11.CKK_ML_KEM)
	pubHandle, err := findKey(session, id, label, uintPtr(pkcs11.CKO_PUBLIC_KEY), &keyType)
	if err != nil {
		// Some tokens (e.g. CloudHSM) reject searches with an empty label attribute.
		p11Err, ok := err.(pkcs11.Error)
		if len(label) == 0 && ok && p11Err == pkcs11.CKR_TEMPLATE_INCONSISTENT {
			pubHandle, err = findKey(session, id, nil, uintPtr(pkcs11.CKO_PUBLIC_KEY), &keyType)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if pubHandle == nil {
		// Try again with ID only in case label search returned nothing.
		pubHandle, err = findKey(session, id, nil, uintPtr(pkcs11.CKO_PUBLIC_KEY), &keyType)
		if err != nil {
			return nil, err
		}
	}
	if pubHandle == nil {
		return nil, errNoPublicHalf
	}

	return &pkcs11MLKEMKeyPair{
		pkcs11Object: pkcs11Object{handle: *privHandle, context: c},
		pubKeyHandle: *pubHandle,
		paramSet:     paramSet,
	}, nil
}

// FindMLKEMKeyPair retrieves a previously created ML-KEM key pair, or an error if it cannot
// be found. At least one of id or label must be specified.
func (c *Context) FindMLKEMKeyPair(id, label []byte) (MLKEMKeyPair, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	result, err := c.FindMLKEMKeyPairs(id, label)
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("ML-KEM key pair with id=%x and label=%x was not found", id, label)
	}
	return result[0], nil
}

// FindMLKEMKeyPairs retrieves all matching ML-KEM key pairs, or a nil slice if none can be found.
// At least one of id or label must be specified.
func (c *Context) FindMLKEMKeyPairs(id, label []byte) ([]MLKEMKeyPair, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	if len(id) == 0 && len(label) == 0 {
		return nil, fmt.Errorf("id and label cannot both be empty")
	}
	attributes := NewAttributeSet()
	if len(id) > 0 {
		if err := attributes.Set(CkaId, id); err != nil {
			return nil, err
		}
	}
	if len(label) > 0 {
		if err := attributes.Set(CkaLabel, label); err != nil {
			return nil, err
		}
	}
	return c.FindMLKEMKeyPairsWithAttributes(attributes)
}

// FindMLKEMKeyPairsWithAttributes retrieves ML-KEM key pairs matching the given attributes.
// Attributes are matched against the private half; the public half is located by CKA_ID / CKA_LABEL.
// The attribute set must not contain CkaClass.
func (c *Context) FindMLKEMKeyPairsWithAttributes(attributes AttributeSet) ([]MLKEMKeyPair, error) {
	if c.closed.Get() {
		return nil, errClosed
	}
	if _, ok := attributes[CkaClass]; ok {
		return nil, fmt.Errorf("keypair attribute set must not contain CkaClass")
	}

	var keys []MLKEMKeyPair
	err := c.withSession(func(session *pkcs11Session) error {
		privAttrs := attributes.Copy()
		if err := privAttrs.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY); err != nil {
			return err
		}
		if err := privAttrs.Set(CkaKeyType, pkcs11.CKK_ML_KEM); err != nil {
			return err
		}

		privHandles, err := findKeysWithAttributes(session, privAttrs.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range privHandles {
			k, err := c.makeMLKEMKeyPair(session, &privHandle)
			if err == errNoCkaId || err == errNoPublicHalf {
				continue
			}
			if err != nil {
				return err
			}
			keys = append(keys, k)
		}
		return nil
	})
	return keys, err
}
