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

	// checkKey is the public key Sign verifies signatures with when the key was found without its
	// public half (pubKey is nil): read from the private key object itself by rsaCheckKey. It is
	// nil when the token exposes neither.
	checkKey *rsa.PublicKey
}

// rsaCheckKey determines the public key of an RSA private key found without its public half, for
// the check Sign makes on every signature: the private key object's own CKA_MODULUS and
// CKA_PUBLIC_EXPONENT, which are not sensitive, or failing that its CKA_PUBLIC_KEY_INFO. It
// returns nil when the token exposes neither; that key's signatures cannot be checked.
func rsaCheckKey(session *pkcs11Session, priv pkcs11.ObjectHandle) *rsa.PublicKey {
	if pub, err := exportRSAPublicKey(session, priv); err == nil {
		if rpub, ok := pub.(*rsa.PublicKey); ok {
			return rpub
		}
	}
	if info := readAttributes(session, priv, pkcs11.CKA_PUBLIC_KEY_INFO)[0]; len(info) > 0 {
		if pub, err := x509.ParsePKIXPublicKey(info); err == nil {
			if rpub, ok := pub.(*rsa.PublicKey); ok {
				return rpub
			}
		}
	}
	return nil
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
	// An RSA modulus is the product of two odd primes: a zero or even one is not a key.
	if modulus.Sign() <= 0 || modulus.Bit(0) == 0 {
		return nil, errMalformedRSAPublicKey
	}
	var bigExponent = new(big.Int)
	bigExponent.SetBytes(exported[1].Value)
	if bigExponent.BitLen() > 32 {
		return nil, errMalformedRSAPublicKey
	}
	if bigExponent.Sign() < 1 {
		return nil, errMalformedRSAPublicKey
	}
	// BitLen() > 32 was rejected above and Sign() >= 1 guarantees a positive value,
	// so the uint64 exponent fits in a positive int on every supported platform.
	exponent := int(bigExponent.Uint64()) // #nosec G115 -- bounded to 32 bits by the checks above
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
		result := &pkcs11PrivateKeyRSA{pkcs11PrivateKey: resultPkcs11PrivateKey, checkKey: rsaCheckKey(session, *privHandle)}
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

	return onlyMatch(result, fmt.Sprintf("private key with id=%x and label=%x", id, label))
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
		err = attributes.Set(pkcs11.CKA_ID, id)
		if err != nil {
			return nil, err
		}
	}
	if len(label) > 0 {
		err = attributes.Set(pkcs11.CKA_LABEL, label)
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

	if _, ok := attributes[pkcs11.CKA_CLASS]; ok {
		return nil, fmt.Errorf("keypair attribute set must not contain CkaClass")
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}
		if err := c.requirePrivateObject(privAttributes); err != nil {
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

	return onlyMatch(result, fmt.Sprintf("key pair with id=%x and label=%x", id, label))
}

// FindRSAKeyPairs retrieves all matching asymmetric RSA key pairs, or a nil slice if none can be
// found.
// At least one of id and label must be specified.
// The public half is a public key object, or failing that a certificate, carrying the private
// key's CKA_ID (and CKA_LABEL). Any session on the token can create such objects, so each one is
// checked against the private key and one holding a different key is never used. If no public
// half is found, the key is not returned because we cannot implement crypto.Signer or
// SignerDecrypter without the public key.
func (c *Context) FindRSAKeyPairs(id []byte, label []byte) (signer []SignerDecrypter, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if len(id) == 0 && len(label) == 0 {
		return nil, errors.New("id and label cannot both be empty")
	}

	attributes := NewAttributeSet()

	if len(id) > 0 {
		err = attributes.Set(pkcs11.CKA_ID, id)
		if err != nil {
			return nil, err
		}
	}
	if len(label) > 0 {
		err = attributes.Set(pkcs11.CKA_LABEL, label)
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
// The public half is a public key object, or failing that a certificate, carrying the private
// key's CKA_ID (and CKA_LABEL). Any session on the token can create such objects, so each one is
// checked against the private key and one holding a different key is never used. If no public
// half is found, the key is not returned because we cannot implement crypto.Signer or
// SignerDecrypter without the public key.
// Private keys that are not RSA are skipped.
func (c *Context) FindRSAKeyPairsWithAttributes(attributes AttributeSet) (signer []SignerDecrypter, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []SignerDecrypter

	if _, ok := attributes[pkcs11.CKA_CLASS]; ok {
		return nil, fmt.Errorf("keypair attribute set must not contain CkaClass")
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}
		if err := c.requirePrivateObject(privAttributes); err != nil {
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
// The public half is a public key object, or failing that a certificate, carrying the private
// key's CKA_ID (and CKA_LABEL). Any session on the token can create such objects, so each one is
// checked against the private key and one holding a different key is never used. If no public
// half is found, the key is not returned because we cannot implement crypto.Signer or
// SignerDecrypter without the public key.
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
	var decryptErr *rsaDecryptError
	if errors.As(err, &decryptErr) {
		return nil, rsa.ErrDecryption
	}
	return plaintext, err
}

// rsaDecryptError is a failure of C_Decrypt itself. It carries the token's reason as far as the
// session pool, which has to see it to retire a broken session, and Decrypt then reports
// rsa.ErrDecryption, as crypto/rsa does. Which error the token gave (bad padding, wrong length,
// a general error) is what a padding oracle is built from.
type rsaDecryptError struct{ cause error }

func (e *rsaDecryptError) Error() string { return e.cause.Error() }
func (e *rsaDecryptError) Unwrap() error { return e.cause }

func decryptPKCS1v15(session *pkcs11Session, key *pkcs11PrivateKeyRSA, ciphertext []byte, sessionKeyLen int) ([]byte, error) {
	if sessionKeyLen != 0 {
		return nil, errUnsupportedRSAOptions
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	if err := session.ctx.DecryptInit(session.handle, mech, key.handle); err != nil {
		return nil, err
	}
	plaintext, err := opResult(session.ctx.Decrypt(session.handle, ciphertext))
	if err != nil {
		return nil, &rsaDecryptError{err}
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
	plaintext, err := opResult(session.ctx.Decrypt(session.handle, ciphertext))
	if err != nil {
		return nil, &rsaDecryptError{err}
	}
	return plaintext, nil
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

// pssSaltLength resolves opts.SaltLength to the salt length handed to the
// token, rejecting what crypto/rsa rejects: a negative length other than the
// two sentinels, and a salt longer than the modulus can carry. The second check
// needs the public key; without one (a key found by FindRSAPrivateKey, say) an
// explicit length is left to the token to judge.
func pssSaltLength(pubKey crypto.PublicKey, saltLength int, hLen uint) (uint, error) {
	switch saltLength {
	case rsa.PSSSaltLengthAuto:
		return maxPSSSaltLength(pubKey, hLen)
	case rsa.PSSSaltLengthEqualsHash:
		return hLen, nil
	}
	if saltLength < 0 {
		return 0, fmt.Errorf("%w: PSS salt length %d", errUnsupportedRSAOptions, saltLength)
	}
	sLen := uint(saltLength)
	if limit, err := maxPSSSaltLength(pubKey, hLen); err == nil && sLen > limit {
		return 0, rsa.ErrMessageTooLong
	}
	return sLen, nil
}

func signPSS(session *pkcs11Session, key *pkcs11PrivateKeyRSA, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	var hMech, mgf, hLen, sLen uint
	var err error
	if hMech, mgf, hLen, err = hashToPKCS11(opts.Hash); err != nil {
		return nil, err
	}
	// CKM_RSA_PKCS_PSS signs a digest it is told the hash of; one of another
	// length is a caller error, reported as signPKCS1v15 reports it.
	if len(digest) != int(hLen) {
		return nil, fmt.Errorf("digest is %d bytes; %v produces %d", len(digest), opts.Hash, hLen)
	}
	if sLen, err = pssSaltLength(key.pubKey, opts.SaltLength, hLen); err != nil {
		return nil, err
	}
	// The binding marshals CK_RSA_PKCS_PSS_PARAMS itself, so we no longer have
	// to hand-pack three CK_ULONGs and hope the layout matches the token's.
	mech := pkcs11.NewMechanismWithParams(pkcs11.CKM_RSA_PKCS_PSS,
		pkcs11.NewPSSParams(hMech, mgf, int(sLen)))
	if err = session.ctx.SignInit(session.handle, mech, key.handle); err != nil {
		return nil, err
	}
	return opResult(session.ctx.Sign(session.handle, digest))
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
		signature, err = opResult(session.ctx.Sign(session.handle, T))
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
	check := priv.pubKey
	if check == nil && priv.checkKey != nil {
		check = priv.checkKey
	}
	if err := checkRSASignature(check, digest, signature, opts); err != nil {
		return nil, err
	}
	return signature, nil
}

// errRSASignatureCheck is returned when a signature the token produced does not verify.
var errRSASignatureCheck = errors.New("crypto11: RSA signature from the token does not verify; it was not returned")

// checkRSASignature verifies a signature the token returned before it is released. An RSA-CRT
// signature computed with a fault, in the token's hardware or software, reveals the private key to
// anyone who holds it and the public key, so one that does not verify is never returned. The
// public key is the key pair's public half, or for a private key found alone the one rsaCheckKey
// read from it. Only a key whose token exposes no public key at all, or one shorter than the 1024
// bits crypto/rsa will verify with, is not checked.
func checkRSASignature(pub crypto.PublicKey, digest, signature []byte, opts crypto.SignerOpts) error {
	rpub, ok := pub.(*rsa.PublicKey)
	if !ok || rpub == nil || rpub.N.BitLen() < 1024 {
		return nil
	}
	var err error
	if o, ok := opts.(*rsa.PSSOptions); ok {
		err = rsa.VerifyPSS(rpub, o.Hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: o.Hash})
	} else {
		err = rsa.VerifyPKCS1v15(rpub, opts.HashFunc(), digest, signature)
	}
	if err != nil {
		return errRSASignatureCheck
	}
	return nil
}
