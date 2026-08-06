// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/pkg/errors"
)

// FindCertificate retrieves a previously imported certificate. Any combination of id, label
// and serial can be provided. An error is return if all are nil.
func findCertificate(session *pkcs11Session, id []byte, label []byte, serial *big.Int) (cert *x509.Certificate, err error) {

	rawCertificate, err := findRawCertificate(session, id, label, serial)
	if err != nil {
		return nil, err
	}

	if rawCertificate != nil {
		cert, err = parseCertificateValue(rawCertificate)
		if err != nil {
			return nil, err
		}
	}

	return cert, err
}

// parseCertificateValue parses the DER certificate held in a CKA_VALUE attribute.
//
// Some tokens return CKA_VALUE in a fixed-size buffer, null-padded past the end of the
// certificate, which x509.ParseCertificate rejects as trailing data. The certificate is
// therefore delimited by its own ASN.1 length rather than by trimming null bytes: a
// certificate whose last byte is legitimately zero — roughly one in 256, the final byte of
// the signature being effectively random — would otherwise be truncated. Anything left over
// must be padding; a non-zero byte past the certificate means the attribute is not what it
// claims to be, and is reported instead of ignored.
func parseCertificateValue(rawCertificate []byte) (*x509.Certificate, error) {
	var der asn1.RawValue
	rest, err := asn1.Unmarshal(rawCertificate, &der)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to decode certificate DER")
	}

	for _, b := range rest {
		if b != 0 {
			return nil, errors.Errorf("%d bytes of non-null trailing data after certificate", len(rest))
		}
	}

	return x509.ParseCertificate(der.FullBytes)
}

func findRawCertificate(session *pkcs11Session, id []byte, label []byte, serial *big.Int) (rawCertificate []byte, err error) {
	if id == nil && label == nil && serial == nil {
		return nil, errors.New("id, label and serial cannot all be nil")
	}

	var template []*pkcs11.Attribute

	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if serial != nil {
		derSerial, err := asn1.Marshal(serial)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to encode serial")
		}

		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, derSerial))
	}

	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))

	if err = session.ctx.FindObjectsInit(session.handle, template); err != nil {
		return nil, err
	}
	defer func() {
		finalErr := session.ctx.FindObjectsFinal(session.handle)
		if err == nil {
			err = finalErr
		}
	}()

	handles, err := session.ctx.FindObjects(session.handle, 1)
	if err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, nil
	}

	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
	}

	if attributes, err = session.ctx.GetAttributeValue(session.handle, handles[0], attributes); err != nil {
		return nil, err
	}

	rawCertificate = attributes[0].Value

	return
}

// FindCertificate retrieves a previously imported certificate. Any combination of id, label
// and serial can be provided. An error is return if all are nil.
func (c *Context) FindCertificate(id []byte, label []byte, serial *big.Int) (*x509.Certificate, error) {

	if c.closed.Get() {
		return nil, errClosed
	}

	var cert *x509.Certificate
	err := c.withSession(func(session *pkcs11Session) (err error) {
		cert, err = findCertificate(session, id, label, serial)
		return err
	})

	return cert, err
}

// FindCertificateChain retrieves a previously imported certificate together with the issuers
// above it that the token also holds, leaf first. The leaf is located exactly as FindCertificate
// locates it — any combination of id, label and serial, an error if all three are nil — and a nil
// slice is returned if it is not on the token.
//
// Each subsequent certificate is the issuer of the one before it. Candidates are matched on
// CKA_SUBJECT against the previous certificate's issuer name, falling back to a scan for a subject
// key identifier equal to its authority key identifier when no subject matches. Names alone do not
// decide it: a candidate is accepted only once it is shown to have signed the certificate below
// it, so a token holding two CAs with the same distinguished name — a renewed or cross-signed CA,
// which is not unusual — yields the one the chain was really built with rather than whichever the
// token happened to return first.
//
// The chain ends at the first self-issued certificate. It is returned short rather than as an
// error when the next issuer is not on the token: a root kept in the caller's system trust store
// instead of on the HSM is the ordinary arrangement, not a failure. A short chain therefore means
// either that the issuer is absent or that nothing on the token signed the last certificate.
//
// Verifying each link is not verifying the chain. Expiry, name constraints, key usage and trust
// are not checked, and being on the token is not a statement of trust — anyone able to write to it
// can add a certificate. A caller must still validate the result, typically with
// x509.Certificate.Verify.
func (c *Context) FindCertificateChain(id []byte, label []byte, serial *big.Int) (chain []*x509.Certificate, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	err = c.withSession(func(session *pkcs11Session) error {
		leaf, err := findCertificate(session, id, label, serial)
		if err != nil {
			return err
		}
		if leaf == nil {
			return nil
		}

		chain, err = findIssuerChain(session, leaf)
		return err
	})

	if err != nil {
		return nil, err
	}

	return chain, nil
}

// findIssuerChain walks from leaf up through the issuers held on the token, stopping at a
// self-issued certificate or at the first issuer it cannot find.
//
// The walk is iterative and keeps every certificate it has already placed, so that a cycle — two
// CAs cross-signing each other, say — terminates instead of running until the stack is exhausted.
// Token contents are not necessarily under the caller's control: anything that can write to the
// token decides how long this runs.
func findIssuerChain(session *pkcs11Session, leaf *x509.Certificate) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{leaf}
	placed := map[string]bool{string(leaf.Raw): true}

	for {
		current := chain[len(chain)-1]

		// A self-issued certificate is the top of the chain: following its issuer name would
		// only lead back to itself.
		if len(current.RawIssuer) == 0 || bytes.Equal(current.RawIssuer, current.RawSubject) {
			return chain, nil
		}

		issuer, err := findIssuer(session, current, placed)
		if err != nil {
			return nil, err
		}
		if issuer == nil {
			return chain, nil
		}

		chain = append(chain, issuer)
		placed[string(issuer.Raw)] = true
	}
}

// findIssuer returns the certificate on the token that signed cert, or nil if there is none.
// Certificates already placed in the chain are not considered again.
//
// The subject search is what the token can answer directly. The authority key identifier scan
// behind it costs a read of every certificate on the token, so it is a fallback rather than the
// first move, and is skipped entirely when cert names no authority key identifier — an empty one
// would otherwise match every certificate that has no subject key identifier.
func findIssuer(session *pkcs11Session, cert *x509.Certificate, placed map[string]bool) (*x509.Certificate, error) {
	candidates, err := findX509Certificates(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawIssuer),
	})
	if err != nil {
		return nil, err
	}

	if issuer := selectIssuer(cert, candidates, placed); issuer != nil {
		return issuer, nil
	}

	if len(cert.AuthorityKeyId) == 0 {
		return nil, nil
	}

	// Not every token indexes CKA_SUBJECT usefully, and a certificate can be imported with a
	// subject attribute that does not match the DER it holds, so the identifiers carried inside
	// the certificates get a second chance at the link.
	all, err := findX509Certificates(session, nil)
	if err != nil {
		return nil, err
	}

	var byKeyID []*x509.Certificate
	for _, candidate := range all {
		if bytes.Equal(candidate.SubjectKeyId, cert.AuthorityKeyId) {
			byKeyID = append(byKeyID, candidate)
		}
	}

	return selectIssuer(cert, byKeyID, placed), nil
}

// selectIssuer returns the first candidate that actually signed cert, or nil if none did. The
// signature is what settles it, since a distinguished name or a key identifier is only a hint:
// both are chosen by whoever issued the certificate and neither is unique on a token that holds
// several generations of the same CA.
func selectIssuer(cert *x509.Certificate, candidates []*x509.Certificate, placed map[string]bool) *x509.Certificate {
	for _, candidate := range candidates {
		if placed[string(candidate.Raw)] {
			continue
		}

		if cert.CheckSignatureFrom(candidate) == nil {
			return candidate
		}
	}

	return nil
}

// FindAllCertificates retrieves every X.509 certificate on the token, or a nil slice if there
// are none. It is the unfiltered counterpart of FindCertificate, for callers that know nothing
// about what the token holds.
//
// Only objects whose CKA_CERTIFICATE_TYPE is CKC_X_509 are returned; certificate objects of
// another type (WTLS or attribute certificates) are not X.509 certificates and are left to the
// token rather than reported as an error. An object that claims to be X.509 but whose CKA_VALUE
// does not parse is reported, since that is corruption rather than a kind of certificate this
// package cannot represent.
//
// Certificates are not matched against private keys. Use FindAllPairedCertificates for the
// certificates this token can also sign with.
//
// The certificates are returned as stored. Being on the token is not a statement of trust —
// anyone able to write to it can add a certificate — so a caller building a trust store or
// verifying a chain must still validate them.
func (c *Context) FindAllCertificates() (certificates []*x509.Certificate, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	err = c.withSession(func(session *pkcs11Session) (err error) {
		certificates, err = findX509Certificates(session, nil)
		return err
	})

	if err != nil {
		return nil, err
	}

	return certificates, nil
}

// findX509Certificates returns every X.509 certificate object matching the given attributes, or a
// nil slice if there are none. The class and certificate type are added to the template, so that
// callers say only what distinguishes the certificates they want; passing nil matches every X.509
// certificate on the token.
//
// An object that claims to be X.509 but whose CKA_VALUE does not parse fails the call rather than
// being skipped, here as in FindAllCertificates: that is corruption, not a kind of certificate
// this package cannot represent.
func findX509Certificates(session *pkcs11Session, attributes []*pkcs11.Attribute) (certificates []*x509.Certificate, err error) {
	template := append([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	}, attributes...)

	// findKeysWithAttributes is not key-specific: it pages C_FindObjects over whatever class the
	// template names. Certificates go through it as well, so that getting the batching right —
	// C_FindObjects returns no more handles than it is asked for — is done in one place rather
	// than two.
	handles, err := findKeysWithAttributes(session, template)
	if err != nil {
		return nil, err
	}

	for _, handle := range handles {
		values := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
		}
		if values, err = session.ctx.GetAttributeValue(session.handle, handle, values); err != nil {
			return nil, err
		}

		certificate, err := parseCertificateValue(values[0].Value)
		if err != nil {
			return nil, errors.WithMessage(err, describeCertificateObject(session, handle))
		}

		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// describeCertificateObject names a certificate object by its CKA_ID and CKA_LABEL, so that an
// error raised while enumerating a token full of certificates says which one is at fault. It is
// best effort: a token that will not report those attributes still gets an error, just a vaguer
// one. The label is quoted rather than interpolated raw, since it is arbitrary bytes chosen by
// whoever wrote the object.
func describeCertificateObject(session *pkcs11Session, handle pkcs11.ObjectHandle) string {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}

	// The error is deliberately dropped: a hard failure comes back with no attributes, while
	// an attribute the token declines to report comes back empty alongside the ones it did
	// read, which is still enough to name the object. Either way the caller's error stands.
	attributes, _ := session.ctx.GetAttributeValue(session.handle, handle, template)
	if len(attributes) < len(template) {
		return "certificate object"
	}

	return fmt.Sprintf("certificate with id=%x and label=%q", attributes[0].Value, attributes[1].Value)
}

// FindAllPairedCertificates finds all certificates on the token that have a matching private key.
func (c *Context) FindAllPairedCertificates() (certificates []tls.Certificate, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := AttributeSet{}
		err = privAttributes.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range privHandles {

			privateKey, certificate, err := c.makeKeyPair(session, &privHandle)

			if errors.Is(err, errNoCkaID) || errors.Is(err, errNoPublicHalf) ||
				errors.Is(err, errUnsupportedKeyType) {
				continue
			}

			if err != nil {
				return err
			}

			if certificate == nil {
				continue
			}

			tlsCert := tls.Certificate{
				Leaf:       certificate,
				PrivateKey: privateKey,
			}

			tlsCert.Certificate = append(tlsCert.Certificate, certificate.Raw)
			certificates = append(certificates, tlsCert)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return
}

// ImportCertificate imports a certificate onto the token. The id parameter is used to
// set CKA_ID and must be non-nil.
func (c *Context) ImportCertificate(id []byte, certificate *x509.Certificate) error {
	if c.closed.Get() {
		return errClosed
	}

	if err := notNilBytes(id, "id"); err != nil {
		return err
	}

	template, err := NewAttributeSetWithID(id)
	if err != nil {
		return err
	}
	return c.ImportCertificateWithAttributes(template, certificate)
}

// ImportCertificateWithLabel imports a certificate onto the token.  The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (c *Context) ImportCertificateWithLabel(id []byte, label []byte, certificate *x509.Certificate) error {
	if c.closed.Get() {
		return errClosed
	}

	if err := notNilBytes(id, "id"); err != nil {
		return err
	}
	if err := notNilBytes(label, "label"); err != nil {
		return err
	}

	template, err := NewAttributeSetWithIDAndLabel(id, label)
	if err != nil {
		return err
	}
	return c.ImportCertificateWithAttributes(template, certificate)
}

// ImportCertificateWithAttributes imports a certificate onto the token. After this function returns, template
// will contain the attributes applied to the certificate. If required attributes are missing, they will be set to a
// default value.
func (c *Context) ImportCertificateWithAttributes(template AttributeSet, certificate *x509.Certificate) error {
	if c.closed.Get() {
		return errClosed
	}

	if certificate == nil {
		return errors.New("certificate cannot be nil")
	}

	serial, err := asn1.Marshal(certificate.SerialNumber)
	if err != nil {
		return err
	}

	template.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, certificate.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, certificate.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certificate.Raw),
	})

	err = c.withSession(func(session *pkcs11Session) error {
		_, err = session.ctx.CreateObject(session.handle, template.ToSlice())
		return err
	})

	return err
}

// DeleteCertificate destroys a previously imported certificate. it will return
// nil if succeeds or if the certificate does not exist. Any combination of id,
// label and serial can be provided. An error is return if all are nil.
func (c *Context) DeleteCertificate(id []byte, label []byte, serial *big.Int) error {
	if id == nil && label == nil && serial == nil {
		return errors.New("id, label and serial cannot all be nil")
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}

	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if serial != nil {
		asn1Serial, err := asn1.Marshal(serial)
		if err != nil {
			return err
		}
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, asn1Serial))
	}

	err := c.withSession(func(session *pkcs11Session) error {
		err := session.ctx.FindObjectsInit(session.handle, template)
		if err != nil {
			return err
		}
		handles, err := session.ctx.FindObjects(session.handle, 1)
		finalErr := session.ctx.FindObjectsFinal(session.handle)
		if err != nil {
			return err
		}
		if finalErr != nil {
			return finalErr
		}
		if len(handles) == 0 {
			return nil
		}
		return session.ctx.DestroyObject(session.handle, handles[0])
	})

	return err
}
