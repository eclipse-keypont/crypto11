// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// errMalformedRSAPublicKey is returned when an RSA public key is not in a suitable form.
//
// Currently this means that the public exponent is either bigger than
// 32 bits, or less than 2.
var errMalformedRSAPublicKey = errors.New("malformed RSA public key")

// errUnsupportedRSAOptions is returned when an unsupported RSA option is requested.
//
// Currently this means a nontrivial SessionKeyLen when decrypting; an
// unsupported hash function; or crypto.rsa.PSSSaltLengthAuto requested
// for a key whose public half is not an RSA public key.
var errUnsupportedRSAOptions = errors.New("unsupported RSA option value")

// pkcs11PrivateKeyRSA contains a reference to a loaded PKCS#11 RSA private key object.
type pkcs11PrivateKeyRSA struct {
	pkcs11PrivateKey
}

// Export the public key corresponding to a private RSA key.
func exportRSAPublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	exported, err := session.ctx.GetAttributeValue(session.handle, pubHandle, template)
	if err != nil {
		return nil, err
	}
	var modulus = new(big.Int)
	modulus.SetBytes(exported[0].Value)
	var bigExponent = new(big.Int)
	bigExponent.SetBytes(exported[1].Value)
	if bigExponent.BitLen() > 32 {
		return nil, errMalformedRSAPublicKey
	}
	if bigExponent.Sign() < 1 {
		return nil, errMalformedRSAPublicKey
	}
	exponent := int(bigExponent.Uint64())
	result := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}
	if result.E < 2 {
		return nil, errMalformedRSAPublicKey
	}
	return &result, nil
}

func (priv *pkcs11PrivateKeyRSA) KeyType() uint {
	return pkcs11.CKK_RSA
}

// GenerateRSAKeyPair creates an RSA key pair on the token. The id parameter is used to
// set CKA_ID and must be non-nil. RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func (c *Context) GenerateRSAKeyPair(id []byte, bits int) (SignerDecrypter, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithID(id)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateRSAKeyPairWithAttributes(public, private, bits)
}

// GenerateRSAKeyPairWithLabel creates an RSA key pair on the token. The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil. RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func (c *Context) GenerateRSAKeyPairWithLabel(id, label []byte, bits int) (SignerDecrypter, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	public, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return nil, err
	}
	// Copy the AttributeSet to allow modifications.
	private := public.Copy()

	return c.GenerateRSAKeyPairWithAttributes(public, private, bits)
}

// GenerateRSAKeyPairWithAttributes generates an RSA key pair on the token. After this function returns, public and
// private will contain the attributes applied to the key pair. If required attributes are missing, they will be set to
// a default value.
func (c *Context) GenerateRSAKeyPairWithAttributes(public, private AttributeSet, bits int) (SignerDecrypter, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var k SignerDecrypter

	err := c.withSession(func(session *pkcs11Session) error {

		public.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
		})
		private.AddIfNotPresent([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, c.defaultPrivate()),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		})

		mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
		pubHandle, privHandle, err := session.ctx.GenerateKeyPair(session.handle,
			mech,
			public.ToSlice(),
			private.ToSlice())
		if err != nil {
			return err
		}

		pub, err := exportRSAPublicKey(session, pubHandle)
		if err != nil {
			return destroyKeyPair(session, pubHandle, privHandle, err)
		}
		k = &pkcs11PrivateKeyRSA{
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

// Takes a handles to the private half of a keypair.
func (c *Context) makeRSAPrivateKey(session *pkcs11Session, privHandle *pkcs11.ObjectHandle) (pk RSAPrivateKey, err error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.ctx.GetAttributeValue(session.handle, *privHandle, attributes); err != nil {
		return nil, err
	}
	keyType := pkcs11.BytesToULong(attributes[0].Value)

	resultPkcs11PrivateKey := pkcs11PrivateKey{
		pkcs11Object: pkcs11Object{
			handle:  *privHandle,
			context: c,
		},
	}

	switch keyType {
	case pkcs11.CKK_RSA:
		result := &pkcs11PrivateKeyRSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		return result, nil

	default:
		return nil, fmt.Errorf("not an RSA key type: %X: %w", keyType, errUnsupportedKeyType)
	}
}

// FindRSAPrivateKey retrieves a previously created asymmetric RSA private key, or nil if it cannot
// be found.
// At least one of id or label must be specified.
// This method is specific to rsa only because it is the only supported type able to decrypt and
// sign.
func (c *Context) FindRSAPrivateKey(id []byte, label []byte) (RSAPrivateKey, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	result, err := c.FindRSAPrivateKeys(id, label)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("private key with id=%x and label=%x was not found or is empty", id, label)
	}

	return result[0], nil
}

// FindRSAPrivateKeys retrieves all matching asymmetric RSA private keys, or a nil slice if none can
// be found.
// At least one of id or label must be specified.
// This method is specific to rsa only because it is the only supported type able to decrypt and
// sign.
func (c *Context) FindRSAPrivateKeys(id []byte, label []byte) (pks []RSAPrivateKey, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if len(id) == 0 && len(label) == 0 {
		return nil, errors.New("id and label cannot both be empty")
	}

	attributes := NewAttributeSet()

	if len(id) > 0 {
		err = attributes.Set(CkaId, id)
		if err != nil {
			return nil, err
		}
	}
	if len(label) > 0 {
		err = attributes.Set(CkaLabel, label)
		if err != nil {
			return nil, err
		}
	}

	return c.FindRSAPrivateKeysWithAttributes(attributes)
}

// FindRSAPrivateKeysWithAttributes retrieves previously created asymmetric RSA private keys,
// or nil if none can be found.
// The given attributes are matched against the private half only.
// Private keys that are not RSA are skipped.
// This method is specific to rsa only because it is the only supported type able to decrypt and
// sign.
func (c *Context) FindRSAPrivateKeysWithAttributes(attributes AttributeSet) (pks []RSAPrivateKey, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []RSAPrivateKey

	if _, ok := attributes[CkaClass]; ok {
		return nil, fmt.Errorf("keypair attribute set must not contain CkaClass")
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range privHandles {
			k, err := c.makeRSAPrivateKey(session, &privHandle)
			if errors.Is(err, errUnsupportedKeyType) {
				continue
			}
			if err != nil {
				return err
			}

			keys = append(keys, k)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keys, nil
}

// makeRSAKeyPair is a method to specifically build an RSA key pair from a pkcs11 session.
// This method is different from makeKeyPair which only return a Signer interface, thus unable to
// decrypt data from the private part of the pair.
// This method is different from makeRSAPrivateKey which only returns a private, thus unable to
// provide the public part of the pair.
func (c *Context) makeRSAKeyPair(session *pkcs11Session, privHandle *pkcs11.ObjectHandle) (signer SignerDecrypter, certificate *x509.Certificate, err error) {
	pubHandle, keyType, resultPkcs11PrivateKey, certificate, pub, err := c.getKeyPair(session, privHandle)
	if err != nil {
		return nil, nil, err
	}

	switch keyType {
	case pkcs11.CKK_RSA:
		result := &pkcs11PrivateKeyRSA{pkcs11PrivateKey: *resultPkcs11PrivateKey}
		if pubHandle != nil {
			if pub, err = exportRSAPublicKey(session, *pubHandle); err != nil {
				return nil, nil, err
			}
			result.pubKeyHandle = *pubHandle
		}

		result.pubKey = pub
		return result, certificate, nil

	default:
		return nil, nil, fmt.Errorf("not an RSA key pair: %X: %w", keyType, errUnsupportedKeyType)
	}
}

// FindRSAKeyPair retrieves a previously created asymmetric RSA key pair, or nil if it cannot
// be found.
// At least one of id or label must be specified.
// This method is specific to rsa only because it is the only supported type able to decrypt and
// sign.
func (c *Context) FindRSAKeyPair(id []byte, label []byte) (SignerDecrypter, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	result, err := c.FindRSAKeyPairs(id, label)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("key pair with id=%x and label=%x was not found or is empty", id, label)
	}

	return result[0], nil
}

// FindRSAKeyPairs retrieves all matching asymmetric RSA key pairs, or a nil slice if none can be
// found.
// At least one of id and label must be specified.
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the
// matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is
// not returned because we cannot implement crypto.Signer or SignerDecrypter without the public key.
func (c *Context) FindRSAKeyPairs(id []byte, label []byte) (signer []SignerDecrypter, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if len(id) == 0 && len(label) == 0 {
		return nil, errors.New("id and label cannot both be empty")
	}

	attributes := NewAttributeSet()

	if len(id) > 0 {
		err = attributes.Set(CkaId, id)
		if err != nil {
			return nil, err
		}
	}
	if len(label) > 0 {
		err = attributes.Set(CkaLabel, label)
		if err != nil {
			return nil, err
		}
	}

	return c.FindRSAKeyPairsWithAttributes(attributes)
}

// FindRSAKeyPairsWithAttributes retrieves previously created RSA asymmetric key pairs, or nil if
// none can be found.
// The given attributes are matched against the private half only. Then the public half with a
// matching CKA_ID and CKA_LABEL values is found.
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the
// matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is
// not returned because we cannot implement crypto.Signer or SignerDecrypter without the public key.
// Private keys that are not RSA are skipped.
func (c *Context) FindRSAKeyPairsWithAttributes(attributes AttributeSet) (signer []SignerDecrypter, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []SignerDecrypter

	if _, ok := attributes[CkaClass]; ok {
		return nil, fmt.Errorf("keypair attribute set must not contain CkaClass")
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range privHandles {
			k, _, err := c.makeRSAKeyPair(session, &privHandle)

			if errors.Is(err, errNoCkaID) || errors.Is(err, errNoPublicHalf) ||
				errors.Is(err, errUnsupportedKeyType) {
				continue
			}
			if err != nil {
				return err
			}

			keys = append(keys, k)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keys, nil
}

// FindAllRSAKeyPairs retrieves all existing RSA asymmetric key pairs, or a nil slice if none can be
// found. It is the decryption-capable counterpart of FindAllKeyPairs: every returned key is a
// SignerDecrypter, so this is the one-call form of "give me everything on this token I can decrypt
// with".
//
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the
// matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is
// not returned because we cannot implement crypto.Signer or SignerDecrypter without the public key.
// Private keys that are not RSA are skipped.
func (c *Context) FindAllRSAKeyPairs() ([]SignerDecrypter, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	return c.FindRSAKeyPairsWithAttributes(NewAttributeSet())
}

// Decrypt decrypts a message using a RSA key.
//
// This completes the implemention of crypto.Decrypter for pkcs11PrivateKeyRSA.
//
// Prefer OAEP (rsa.OAEPOptions) for new designs. PKCS#1 v1.5 decryption —
// selected by nil options or rsa.PKCS1v15DecryptOptions — is unpadded by the
// token, and a caller that lets a remote party distinguish success from
// failure, or time the two, exposes a Bleichenbacher padding oracle against
// every ciphertext under the key. The stdlib's countermeasure, SessionKeyLen,
// cannot be implemented on top of an HSM that reports the padding error, so
// it is not supported and a nonzero value is an error. All v1.5 decryption
// failures are reported as rsa.ErrDecryption, without the token's reason.
//
// The underlying PKCS#11 implementation may impose further restrictions.
func (priv *pkcs11PrivateKeyRSA) Decrypt(_ io.Reader, ciphertext []byte, options crypto.DecrypterOpts) (plaintext []byte, err error) {
	err = priv.context.withSession(func(session *pkcs11Session) error {
		if options == nil {
			plaintext, err = decryptPKCS1v15(session, priv, ciphertext, 0)
		} else {
			switch o := options.(type) {
			case *rsa.PKCS1v15DecryptOptions:
				plaintext, err = decryptPKCS1v15(session, priv, ciphertext, o.SessionKeyLen)
			case *rsa.OAEPOptions:
				plaintext, err = decryptOAEP(session, priv, ciphertext, o.Hash, o.MGFHash, o.Label)
			default:
				err = errUnsupportedRSAOptions
			}
		}
		return err
	})
	return plaintext, err
}

func decryptPKCS1v15(session *pkcs11Session, key *pkcs11PrivateKeyRSA, ciphertext []byte, sessionKeyLen int) ([]byte, error) {
	if sessionKeyLen != 0 {
		return nil, errUnsupportedRSAOptions
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	if err := session.ctx.DecryptInit(session.handle, mech, key.handle); err != nil {
		return nil, err
	}
	plaintext, err := session.ctx.Decrypt(session.handle, ciphertext)
	if err != nil {
		// The token's reason — bad padding, wrong length — is exactly what a
		// padding oracle is built from. Collapse it to the error crypto/rsa
		// itself uses, unless the session is what failed: that one has to stay
		// visible so the pool can recycle it.
		var p11Err pkcs11.Error
		if errors.As(err, &p11Err) && (p11Err == pkcs11.CKR_ENCRYPTED_DATA_INVALID || p11Err == pkcs11.CKR_ENCRYPTED_DATA_LEN_RANGE) {
			return nil, rsa.ErrDecryption
		}
		return nil, err
	}
	return plaintext, nil
}

func decryptOAEP(session *pkcs11Session, key *pkcs11PrivateKeyRSA, ciphertext []byte, hashFunction, mgfHash crypto.Hash,
	label []byte) ([]byte, error) {

	hashAlg, _, _, err := hashToPKCS11(hashFunction)
	if err != nil {
		return nil, err
	}
	// rsa.OAEPOptions selects the MGF1 hash separately, defaulting to Hash
	// only when it is zero. Deriving it from Hash unconditionally silently
	// decrypted under different parameters than the caller asked for.
	if mgfHash == 0 {
		mgfHash = hashFunction
	}
	_, mgfAlg, _, err := hashToPKCS11(mgfHash)
	if err != nil {
		return nil, err
	}

	mech := pkcs11.NewMechanismWithParams(pkcs11.CKM_RSA_PKCS_OAEP,
		pkcs11.NewOAEPParams(hashAlg, mgfAlg, pkcs11.CKZ_DATA_SPECIFIED, label))

	err = session.ctx.DecryptInit(session.handle, mech, key.handle)
	if err != nil {
		return nil, err
	}
	return session.ctx.Decrypt(session.handle, ciphertext)
}

func hashToPKCS11(hashFunction crypto.Hash) (hashAlg uint, mgfAlg uint, hashLen uint, err error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, errUnsupportedRSAOptions
	}
}

// maxPSSSaltLength resolves rsa.PSSSaltLengthAuto to the largest salt the
// modulus can carry, the same value crypto/rsa picks: emLen - hLen - 2, with
// emLen derived from the bit length of the modulus.
func maxPSSSaltLength(pubKey crypto.PublicKey, hLen uint) (uint, error) {
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return 0, errUnsupportedRSAOptions
	}
	sLen := (pub.N.BitLen()-1+7)/8 - 2 - int(hLen)
	if sLen < 0 {
		return 0, rsa.ErrMessageTooLong
	}
	return uint(sLen), nil
}

func signPSS(session *pkcs11Session, key *pkcs11PrivateKeyRSA, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	var hMech, mgf, hLen, sLen uint
	var err error
	if hMech, mgf, hLen, err = hashToPKCS11(opts.Hash); err != nil {
		return nil, err
	}
	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto:
		if sLen, err = maxPSSSaltLength(key.pubKey, hLen); err != nil {
			return nil, err
		}
	case rsa.PSSSaltLengthEqualsHash:
		sLen = hLen
	default:
		sLen = uint(opts.SaltLength)
	}
	// The binding marshals CK_RSA_PKCS_PSS_PARAMS itself, so we no longer have
	// to hand-pack three CK_ULONGs and hope the layout matches the token's.
	mech := pkcs11.NewMechanismWithParams(pkcs11.CKM_RSA_PKCS_PSS,
		pkcs11.NewPSSParams(hMech, mgf, int(sLen)))
	if err = session.ctx.SignInit(session.handle, mech, key.handle); err != nil {
		return nil, err
	}
	return session.ctx.Sign(session.handle, digest)
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func signPKCS1v15(session *pkcs11Session, key *pkcs11PrivateKeyRSA, digest []byte, hash crypto.Hash) (signature []byte, err error) {
	/* Calculate T for EMSA-PKCS1-v1_5. */
	var oid []byte
	if hash != 0 {
		// crypto.Hash(0) asks for the digest to be signed as it is, without
		// a DigestInfo — a legitimate request. A hash the table does not know
		// is not: signing the bare digest then would produce a signature under
		// a different algorithm than the one named, and the token cannot tell,
		// since CKM_RSA_PKCS only ever sees the assembled bytes.
		var ok bool
		if oid, ok = pkcs1Prefix[hash]; !ok {
			return nil, fmt.Errorf("%w: no PKCS#1 v1.5 DigestInfo for %v", errUnsupportedRSAOptions, hash)
		}
		if len(digest) != hash.Size() {
			return nil, fmt.Errorf("digest is %d bytes; %v produces %d", len(digest), hash, hash.Size())
		}
	}
	T := make([]byte, len(oid)+len(digest))
	copy(T[0:len(oid)], oid)
	copy(T[len(oid):], digest)
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	err = session.ctx.SignInit(session.handle, mech, key.handle)
	if err == nil {
		signature, err = session.ctx.Sign(session.handle, T)
	}
	return
}

// Sign signs a message using a RSA key.
//
// This completes the implemention of crypto.Signer for pkcs11PrivateKeyRSA.
//
// PKCS#11 expects to pick its own random data where necessary for signatures, so the rand argument is ignored.
//
// For PSS signatures, crypto.rsa.PSSSaltLengthAuto is resolved to the
// largest salt the modulus can carry, as crypto/rsa does; callers may
// also use crypto.rsa.PSSSaltLengthEqualsHash or an explicit salt
// length. Note that the underlying PKCS#11 implementation may impose
// further restrictions on the salt length it accepts.
func (priv *pkcs11PrivateKeyRSA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	err = priv.context.withSession(func(session *pkcs11Session) error {
		switch opts := opts.(type) {
		case *rsa.PSSOptions:
			signature, err = signPSS(session, priv, digest, opts)
		default: /* PKCS1-v1_5 */
			signature, err = signPKCS1v15(session, priv, digest, opts.HashFunc())
		}
		return err
	})

	if err != nil {
		return nil, err
	}

	return signature, err
}
