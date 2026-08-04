// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
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

	err = c.withSession(func(session *pkcs11Session) error {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		}

		// findKeysWithAttributes is not key-specific: it pages C_FindObjects over whatever
		// class the template names. Certificates go through it as well, so that getting the
		// batching right — C_FindObjects returns no more handles than it is asked for — is
		// done in one place rather than two.
		handles, err := findKeysWithAttributes(session, template)
		if err != nil {
			return err
		}

		for _, handle := range handles {
			attributes := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
			}
			if attributes, err = session.ctx.GetAttributeValue(session.handle, handle, attributes); err != nil {
				return err
			}

			certificate, err := parseCertificateValue(attributes[0].Value)
			if err != nil {
				return errors.WithMessage(err, describeCertificateObject(session, handle))
			}

			certificates = append(certificates, certificate)
		}

		return nil
	})

	if err != nil {
		return nil, err
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
