// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// errAmbiguousPublicHalf is returned when the objects that match a private key by CKA_ID and
// CKA_LABEL carry different public keys and none of them can be checked against the private key.
// It wraps errNoPublicHalf, so the enumeration functions skip such a key as they skip one with no
// public half at all.
var errAmbiguousPublicHalf = fmt.Errorf("%w: candidates carry different public keys and none can be verified", errNoPublicHalf)

// Pairing a private key with its public half.
//
// CKA_ID and CKA_LABEL are labels, not proof: PKCS#11 lets any session, including one that has
// not logged in, create public objects (a R/W Public Session has read/write access to them). A
// public key or certificate found by those attributes alone may therefore belong to someone else.
// Every candidate is checked against the private key object itself before it is used:
//
//   - RSA private keys carry CKA_MODULUS (and usually CKA_PUBLIC_EXPONENT), which are not
//     sensitive;
//   - any private key may carry CKA_PUBLIC_KEY_INFO, the DER SubjectPublicKeyInfo of its public
//     half;
//   - otherwise, if the key may sign without a context-specific login, one test signature over
//     random data is verified under each candidate;
//   - ML-KEM keys are checked by encapsulating to the candidate and decapsulating with the
//     private key (see mlkemPairVerifier).
//
// A candidate proven to belong to another key is never used. When nothing can be proven, the
// candidates are accepted only if they all carry the same key.

// pairMatch is the outcome of checking one candidate public key against a private key.
type pairMatch int

const (
	pairUnverified pairMatch = iota // nothing on the private key to check the candidate against
	pairVerified                    // the candidate is the private key's public half
	pairMismatch                    // the candidate belongs to a different key
)

// pubCandidate is a public key that may be the public half of a private key: a public key
// object (handle set) or a certificate (cert set).
type pubCandidate struct {
	handle *pkcs11.ObjectHandle
	cert   *x509.Certificate
	key    crypto.PublicKey
	match  pairMatch
}

// selectPublicHalf picks the public half of a private key from tiers of candidates, in order of
// preference. The first verified candidate wins. Failing that, the first tier holding unverified
// candidates is used if they all carry the same key; if they disagree there is no telling which
// one is genuine, and errAmbiguousPublicHalf is returned. Mismatched candidates are ignored.
func selectPublicHalf(tiers ...[]*pubCandidate) (*pubCandidate, error) {
	for _, tier := range tiers {
		for _, c := range tier {
			if c.match == pairVerified {
				return c, nil
			}
		}
	}
	for _, tier := range tiers {
		var pool []*pubCandidate
		for _, c := range tier {
			if c.match == pairUnverified {
				pool = append(pool, c)
			}
		}
		if len(pool) == 0 {
			continue
		}
		for _, c := range pool[1:] {
			if !publicKeysEqual(pool[0].key, c.key) {
				return nil, errAmbiguousPublicHalf
			}
		}
		return pool[0], nil
	}
	return nil, errNoPublicHalf
}

// publicKeysEqual reports whether a and b are the same public key.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	if equal, ok := dsaPublicKeysEqual(a, b); ok {
		return equal
	}
	if eq, ok := a.(interface{ Equal(crypto.PublicKey) bool }); ok {
		return eq.Equal(b)
	}
	return false
}

// readAttributes reads the given attributes of an object and returns their values, nil for any
// the token does not have or will not reveal. Errors are not reported: the attributes read here
// are optional evidence, and their absence only means less can be verified.
func readAttributes(session *pkcs11Session, handle pkcs11.ObjectHandle, types ...uint) [][]byte {
	template := make([]*pkcs11.Attribute, len(types))
	for i, t := range types {
		template[i] = pkcs11.NewAttribute(t, nil)
	}
	values := make([][]byte, len(types))
	attrs, _ := session.ctx.GetAttributeValue(session.handle, handle, template)
	if len(attrs) != len(types) {
		// A hard failure returns no attributes; asking one at a time still gets the readable ones.
		if len(types) > 1 {
			for i, t := range types {
				values[i] = readAttributes(session, handle, t)[0]
			}
		}
		return values
	}
	for i, a := range attrs {
		values[i] = a.Value
	}
	return values
}

// isTrue reports whether a CK_BBOOL attribute value is set.
func isTrue(v []byte) bool {
	return len(v) > 0 && v[0] != 0
}

// pairVerifier checks candidate public keys against a signing private key.
type pairVerifier struct {
	session *pkcs11Session
	priv    pkcs11.ObjectHandle
	keyType uint

	// rsaN and rsaE are read from an RSA private key; rsaE is 0 when the token does not store it.
	rsaN *big.Int
	rsaE int

	// info is the public key from the private key's CKA_PUBLIC_KEY_INFO, when present.
	info crypto.PublicKey

	// canProbe is set when the private key may sign without a context-specific login. The test
	// signature is made once, on first use, and verified under every candidate.
	canProbe bool
	probeMsg []byte
	probeSig []byte
}

func newPairVerifier(session *pkcs11Session, priv pkcs11.ObjectHandle, keyType uint) *pairVerifier {
	v := &pairVerifier{session: session, priv: priv, keyType: keyType}

	if keyType == pkcs11.CKK_RSA {
		values := readAttributes(session, priv, pkcs11.CKA_MODULUS, pkcs11.CKA_PUBLIC_EXPONENT)
		if len(values[0]) > 0 {
			v.rsaN = new(big.Int).SetBytes(values[0])
			if e := new(big.Int).SetBytes(values[1]); e.Sign() > 0 && e.BitLen() <= 31 {
				v.rsaE = int(e.Int64())
			}
			return v
		}
	}

	if info := readAttributes(session, priv, pkcs11.CKA_PUBLIC_KEY_INFO)[0]; len(info) > 0 {
		if pub, err := x509.ParsePKIXPublicKey(info); err == nil {
			v.info = pub
			return v
		}
	}

	values := readAttributes(session, priv, pkcs11.CKA_SIGN, pkcs11.CKA_ALWAYS_AUTHENTICATE)
	v.canProbe = isTrue(values[0]) && !isTrue(values[1])
	return v
}

// check reports whether pub is the public half of the private key.
func (v *pairVerifier) check(pub crypto.PublicKey) pairMatch {
	switch {
	case v.rsaN != nil:
		rpub, ok := pub.(*rsa.PublicKey)
		if !ok || rpub.N.Cmp(v.rsaN) != 0 || (v.rsaE != 0 && rpub.E != v.rsaE) {
			return pairMismatch
		}
		return pairVerified
	case v.info != nil:
		if publicKeysEqual(v.info, pub) {
			return pairVerified
		}
		return pairMismatch
	case v.canProbe:
		return v.probe(pub)
	}
	return pairUnverified
}

// probe verifies a test signature, made by the private key over random data, under pub.
func (v *pairVerifier) probe(pub crypto.PublicKey) pairMatch {
	if v.probeSig == nil {
		if !v.sign() {
			v.canProbe = false
			return pairUnverified
		}
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var sig dsaSignature
		if sig.unmarshalBytes(v.probeSig) != nil || !ecdsa.Verify(k, v.probeMsg, sig.R, sig.S) {
			return pairMismatch
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize || !ed25519.Verify(k, v.probeMsg, v.probeSig) {
			return pairMismatch
		}
	default:
		if valid, ok := verifyDSASignature(pub, v.probeMsg, v.probeSig); !ok || !valid {
			return pairMismatch
		}
	}
	return pairVerified
}

// sign makes the test signature. It reports false if the token will not sign, in which case
// candidates are left unverified rather than rejected.
func (v *pairVerifier) sign() bool {
	var mechanism uint
	msgLen := 32
	switch v.keyType {
	case pkcs11.CKK_ECDSA:
		mechanism = pkcs11.CKM_ECDSA
	case pkcs11.CKK_EC_EDWARDS:
		mechanism = pkcs11.CKM_EDDSA
	case pkcs11.CKK_DSA:
		// A digest as long as the subgroup order, as tokens expect for CKM_DSA.
		mechanism, msgLen = pkcs11.CKM_DSA, 20
		if q := readAttributes(v.session, v.priv, pkcs11.CKA_SUBPRIME)[0]; len(bytes.TrimLeft(q, "\x00")) > 0 {
			msgLen = len(bytes.TrimLeft(q, "\x00"))
		}
	default:
		return false
	}
	msg := make([]byte, msgLen)
	if _, err := rand.Read(msg); err != nil {
		return false
	}
	if err := v.session.ctx.SignInit(v.session.handle, pkcs11.NewMechanism(mechanism, nil), v.priv); err != nil {
		return false
	}
	sig, err := opResult(v.session.ctx.Sign(v.session.handle, msg))
	if err != nil || len(sig) == 0 {
		return false
	}
	v.probeMsg, v.probeSig = msg, sig
	return true
}

// exportPublicKey reads the public key object pubHandle as a key of the given type.
func exportPublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle, keyType uint) (crypto.PublicKey, error) {
	switch keyType {
	case pkcs11.CKK_DSA:
		return exportDSAPublicKey(session, pubHandle)
	case pkcs11.CKK_RSA:
		return exportRSAPublicKey(session, pubHandle)
	case pkcs11.CKK_ECDSA:
		return exportECDSAPublicKey(session, pubHandle)
	case pkcs11.CKK_EC_EDWARDS:
		return exportEd25519PublicKey(session, pubHandle)
	default:
		return nil, fmt.Errorf("%w: %X", errUnsupportedKeyType, keyType)
	}
}

// findCertificatesByID returns the X.509 certificates on the token whose CKA_ID is id. Objects
// whose value does not parse are left out.
func findCertificatesByID(session *pkcs11Session, id []byte) ([]*x509.Certificate, error) {
	handles, err := findKeysWithAttributes(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, h := range handles {
		value := readAttributes(session, h, pkcs11.CKA_VALUE)[0]
		if cert, err := parseCertificateValue(value); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// spkiPublicKey returns the subjectPublicKey bits of a DER SubjectPublicKeyInfo.
func spkiPublicKey(der []byte) ([]byte, error) {
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%d bytes of trailing data after SubjectPublicKeyInfo", len(rest))
	}
	return spki.PublicKey.RightAlign(), nil
}
