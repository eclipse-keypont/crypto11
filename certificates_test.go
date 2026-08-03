// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	label := randomBytes()

	cert := generateRandomCert(t)

	err = ctx.ImportCertificateWithLabel(id, label, cert)
	require.NoError(t, err)

	cert2, err := ctx.FindCertificate(nil, label, nil)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	assert.Equal(t, cert.Signature, cert2.Signature)

	cert2, err = ctx.FindCertificate(nil, []byte("test2"), nil)
	require.NoError(t, err)
	assert.Nil(t, cert2)

	cert2, err = ctx.FindCertificate(nil, nil, cert.SerialNumber)
	require.NoError(t, err)
	require.NotNil(t, cert2)

	assert.Equal(t, cert.Signature, cert2.Signature)
}

// Test that provided attributes override default values
func TestCertificateAttributes(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	cert := generateRandomCert(t)

	// We import this with a different serial number, to test this is obeyed
	ourSerial := new(big.Int)
	ourSerial.Add(cert.SerialNumber, big.NewInt(1))

	derSerial, err := asn1.Marshal(ourSerial)
	require.NoError(t, err)

	template := NewAttributeSet()
	err = template.Set(CkaSerialNumber, derSerial)
	require.NoError(t, err)

	err = ctx.ImportCertificateWithAttributes(template, cert)
	require.NoError(t, err)

	// Try to find with old serial
	c, err := ctx.FindCertificate(nil, nil, cert.SerialNumber)
	require.NoError(t, err)
	assert.Nil(t, c)

	// Find with new serial
	c, err = ctx.FindCertificate(nil, nil, ourSerial)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestCertificateRequiredArgs(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	cert := generateRandomCert(t)

	val := randomBytes()

	err = ctx.ImportCertificateWithLabel(nil, val, cert)
	require.Error(t, err)

	err = ctx.ImportCertificateWithLabel(val, nil, cert)
	require.Error(t, err)

	err = ctx.ImportCertificateWithLabel(val, val, nil)
	require.Error(t, err)
}

func TestDeleteCertificate(t *testing.T) {
	skipTest(t, skipTestCert)

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	randomCert := func() ([]byte, []byte, *x509.Certificate) {
		id := randomBytes()
		label := randomBytes()
		cert := generateRandomCert(t)
		return id, label, cert
	}
	importCertificate := func() ([]byte, []byte, *big.Int) {
		id, label, cert := randomCert()
		err = ctx.ImportCertificateWithLabel(id, label, cert)
		require.NoError(t, err)

		cert2, err := ctx.FindCertificate(id, label, cert.SerialNumber)
		require.NoError(t, err)
		require.NotNil(t, cert2)
		assert.Equal(t, cert.Signature, cert2.Signature)

		return id, label, cert.SerialNumber
	}

	err = ctx.DeleteCertificate(nil, nil, nil)
	require.Error(t, err)

	id, label, cert := randomCert()
	err = ctx.DeleteCertificate(id, label, cert.SerialNumber)
	require.NoError(t, err)

	id, label, serial := importCertificate()
	err = ctx.DeleteCertificate(id, label, serial)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(id, label, nil)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(id, nil, nil)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(nil, label, nil)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)

	id, label, serial = importCertificate()
	err = ctx.DeleteCertificate(nil, nil, serial)
	require.NoError(t, err)

	cert, err = ctx.FindCertificate(id, label, serial)
	require.NoError(t, err)
	require.Nil(t, cert)
}

func generateRandomCert(t *testing.T) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, big.NewInt(20000))
	require.NoError(t, err)

	ca := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Foo",
		},
		SerialNumber:          serial,
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	csr := &key.PublicKey
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, csr, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}

func TestParseCertificateValue(t *testing.T) {
	plain := generateFastCertDER(t, false)
	endsInNull := generateFastCertDER(t, true)

	padding := make([]byte, 16)

	tests := []struct {
		name string
		der  []byte
	}{
		{"plain", plain},
		{"padded", append(append([]byte{}, plain...), padding...)},
		// A certificate whose signature happens to end in a null byte must survive
		// unpadded, and must not be truncated when the token pads it either.
		{"ends in null byte", endsInNull},
		{"ends in null byte, padded", append(append([]byte{}, endsInNull...), padding...)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := parseCertificateValue(test.der)
			require.NoError(t, err)
			require.NotNil(t, cert)
			assert.Equal(t, "trim-test", cert.Subject.CommonName)
		})
	}
}

func TestParseCertificateValueRejectsGarbage(t *testing.T) {
	der := generateFastCertDER(t, false)

	// Trailing data that is not padding indicates a corrupt or misreported attribute.
	_, err := parseCertificateValue(append(append([]byte{}, der...), 0x00, 0x01, 0x00))
	require.Error(t, err)

	// Leading null bytes are not padding either: the buffer no longer starts with the
	// certificate, and must not be silently reinterpreted.
	_, err = parseCertificateValue(append([]byte{0x00, 0x00}, der...))
	require.Error(t, err)

	_, err = parseCertificateValue(nil)
	require.Error(t, err)

	// A certificate truncated mid-way, then null-padded back to its original length,
	// must not pass as valid.
	truncated := make([]byte, len(der))
	copy(truncated, der[:len(der)/2])
	_, err = parseCertificateValue(truncated)
	require.Error(t, err)
}

// generateFastCertDER returns the DER of a self-signed ECDSA certificate. When endsInNull is
// set, certificates are generated until one whose last byte is zero turns up — the last byte
// of the signature is effectively random, so this takes ~256 attempts.
func generateFastCertDER(t *testing.T, endsInNull bool) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "trim-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	for i := 0; i < 10000; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)

		if !endsInNull || der[len(der)-1] == 0x00 {
			return der
		}
	}

	t.Fatal("no certificate ending in a null byte was generated")
	return nil
}
