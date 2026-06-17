// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: MIT

package crypto11

import (
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
	assert.Nil(t, c)

	// Find with new serial
	c, err = ctx.FindCertificate(nil, nil, ourSerial)
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
