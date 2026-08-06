// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
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

// requireCertificatesFound checks that every wanted certificate appears in got, matching on the
// full DER rather than on an identifier, so the finder is shown to return the right bytes and not
// merely the right number of objects. The token may already hold certificates the test did not
// import, so the assertion is containment rather than an exact count — the counterpart of
// requireKeysFound in keys_test.go, which cannot be reused here because it indexes by CKA_ID
// through Context.GetAttribute, and an x509.Certificate is not a PKCS#11 key.
func requireCertificatesFound(t *testing.T, got, want []*x509.Certificate, msg string) {
	t.Helper()

	require.GreaterOrEqual(t, len(got), len(want), msg)

	found := make(map[string]bool, len(got))
	for _, cert := range got {
		found[string(cert.Raw)] = true
	}

	for _, cert := range want {
		assert.True(t, found[string(cert.Raw)],
			"%s: omitted the certificate with serial %d", msg, cert.SerialNumber)
	}
}

func TestFindAllCertificates(t *testing.T) {
	skipTest(t, skipTestCert)

	tests := []struct {
		name  string
		count int
	}{
		{"a few certificates", 3},
		// C_FindObjects returns no more handles than it is asked for, so enumerating in a
		// single call silently truncates the result at maxHandlePerFind.
		{"more than one batch", maxHandlePerFind + 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withContext(t, func(ctx *Context) {
				want := make([]*x509.Certificate, 0, test.count)

				for i := 0; i < test.count; i++ {
					id := randomBytes()
					cert := generateFastCert(t, int64(i))

					require.NoError(t, ctx.ImportCertificate(id, cert))
					// Delete only what this test imported: the token is not
					// assumed to be ours to clear.
					defer func() {
						require.NoError(t, ctx.DeleteCertificate(id, nil, nil))
					}()

					want = append(want, cert)
				}

				got, err := ctx.FindAllCertificates()
				require.NoError(t, err)

				requireCertificatesFound(t, got, want, "FindAllCertificates")
			})
		})
	}
}

// signedCert is a generated certificate together with the key it was issued with, so that a test
// can go on to sign the certificate below it in a chain.
type signedCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// generateCertChain returns one certificate per name, leaf first — the order FindCertificateChain
// returns them in. The last name is the self-signed root, every other certificate is issued by the
// name after it. Subject and authority key identifiers are set throughout, since the identifier
// fallback in findIssuer has nothing to match on without them.
func generateCertChain(t *testing.T, names ...string) []signedCert {
	t.Helper()

	chain := make([]signedCert, 0, len(names))

	// Built root first, since each certificate needs its issuer's key to exist already.
	for i := len(names) - 1; i >= 0; i-- {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := certTemplate(t, names[i], i > 0)

		parent, signer := template, key
		if issued := len(chain); issued > 0 {
			issuer := chain[issued-1]
			parent, signer = issuer.cert, issuer.key
			template.AuthorityKeyId = issuer.cert.SubjectKeyId
		}

		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		chain = append(chain, signedCert{cert: cert, key: key})
	}

	slices.Reverse(chain)

	return chain
}

// certTemplate returns a certificate template with a random serial and subject key identifier.
func certTemplate(t *testing.T, commonName string, isCA bool) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		SubjectKeyId:          randomBytes(),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
	}
}

// importChain imports every certificate in chain under a fresh CKA_ID and returns the ids, leaf
// first.
func importChain(t *testing.T, ctx *Context, chain []signedCert) [][]byte {
	t.Helper()

	ids := make([][]byte, 0, len(chain))
	for _, link := range chain {
		ids = append(ids, importCert(t, ctx, link.cert))
	}

	return ids
}

// importCert imports one certificate under a fresh CKA_ID and returns it.
func importCert(t *testing.T, ctx *Context, cert *x509.Certificate) []byte {
	t.Helper()

	id := randomBytes()
	require.NoError(t, ctx.ImportCertificate(id, cert))

	return id
}

// deleteCerts removes the certificates a test imported, and only those: the token is not assumed
// to be the test's to clear. It must run before the context closes, so callers defer it inside the
// withContext body rather than registering it with t.Cleanup.
func deleteCerts(t *testing.T, ctx *Context, ids ...[][]byte) {
	t.Helper()

	for _, group := range ids {
		for _, id := range group {
			assert.NoError(t, ctx.DeleteCertificate(id, nil, nil))
		}
	}
}

// requireChainEqual checks that got holds exactly the certificates in want, in order.
func requireChainEqual(t *testing.T, got []*x509.Certificate, want []signedCert) {
	t.Helper()

	require.Len(t, got, len(want))

	for i, link := range want {
		assert.Equal(t, link.cert.Raw, got[i].Raw,
			"chain position %d: expected %q", i, link.cert.Subject.CommonName)
	}
}

func TestFindCertificateChain(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		chain := generateCertChain(t, "chain-leaf", "chain-intermediate", "chain-root")

		ids := importChain(t, ctx, chain)
		defer deleteCerts(t, ctx, ids)

		got, err := ctx.FindCertificateChain(ids[0], nil, nil)
		require.NoError(t, err)

		requireChainEqual(t, got, chain)
	})
}

// A root kept in the caller's system trust store rather than on the HSM is the ordinary
// arrangement, so a chain that runs out of issuers is returned short instead of failing.
func TestFindCertificateChainStopsAtMissingIssuer(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		chain := generateCertChain(t, "partial-leaf", "partial-intermediate", "partial-root")

		ids := importChain(t, ctx, chain[:2])
		defer deleteCerts(t, ctx, ids)

		got, err := ctx.FindCertificateChain(ids[0], nil, nil)
		require.NoError(t, err)

		requireChainEqual(t, got, chain[:2])
	})
}

// Two CAs can share a distinguished name — a renewed or cross-signed CA — so the issuer has to be
// settled by the signature rather than by whichever object the token returns first.
func TestFindCertificateChainIgnoresSameSubjectDecoy(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		names := []string{"decoy-leaf", "decoy-intermediate", "decoy-root"}

		chain := generateCertChain(t, names...)
		decoys := generateCertChain(t, names...)

		// Imported first, so that a finder taking the first match would take the wrong one.
		decoyIDs := importChain(t, ctx, decoys[1:])
		ids := importChain(t, ctx, chain)
		defer deleteCerts(t, ctx, decoyIDs, ids)

		got, err := ctx.FindCertificateChain(ids[0], nil, nil)
		require.NoError(t, err)

		requireChainEqual(t, got, chain)
	})
}

// CKA_SUBJECT is set by whoever imported the certificate and need not agree with the DER it
// holds, so the walk falls back to the authority and subject key identifiers inside the
// certificates themselves.
func TestFindCertificateChainFallsBackToKeyID(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		chain := generateCertChain(t, "keyid-leaf", "keyid-root")

		template, err := NewAttributeSetWithID(randomBytes())
		require.NoError(t, err)

		// A subject the issuer search cannot match, leaving only the key identifier.
		require.NoError(t, template.Set(CkaSubject, randomBytes()))
		require.NoError(t, ctx.ImportCertificateWithAttributes(template, chain[1].cert))

		id := importCert(t, ctx, chain[0].cert)
		defer deleteCerts(t, ctx, [][]byte{id, template[CkaId].Value})

		got, err := ctx.FindCertificateChain(id, nil, nil)
		require.NoError(t, err)

		requireChainEqual(t, got, chain)
	})
}

// Two CAs that cross-sign each other are a cycle in the issuer graph. The walk has to stop rather
// than follow it: anything able to write to the token decides how long the lookup runs.
func TestFindCertificateChainTerminatesOnCycle(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		templateA := certTemplate(t, "cycle-a", true)
		templateB := certTemplate(t, "cycle-b", true)
		templateLeaf := certTemplate(t, "cycle-leaf", false)

		templateA.AuthorityKeyId = templateB.SubjectKeyId
		templateB.AuthorityKeyId = templateA.SubjectKeyId
		templateLeaf.AuthorityKeyId = templateA.SubjectKeyId

		// A is issued by B and B by A, so following issuer names alone never terminates.
		certA := createCert(t, templateA, templateB, &keyA.PublicKey, keyB)
		certB := createCert(t, templateB, templateA, &keyB.PublicKey, keyA)
		leaf := createCert(t, templateLeaf, templateA, &keyA.PublicKey, keyA)

		idA := importCert(t, ctx, certA)
		idB := importCert(t, ctx, certB)
		id := importCert(t, ctx, leaf)
		defer deleteCerts(t, ctx, [][]byte{idA, idB, id})

		got, err := ctx.FindCertificateChain(id, nil, nil)
		require.NoError(t, err)

		require.Len(t, got, 3)
		assert.Equal(t, leaf.Raw, got[0].Raw)
		assert.Equal(t, certA.Raw, got[1].Raw)
		assert.Equal(t, certB.Raw, got[2].Raw)
	})
}

func TestFindCertificateChainNotFound(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		got, err := ctx.FindCertificateChain(randomBytes(), nil, nil)
		require.NoError(t, err)
		assert.Nil(t, got)

		_, err = ctx.FindCertificateChain(nil, nil, nil)
		require.Error(t, err)
	})
}

// A leaf on its own does not verify at a peer that lacks the intermediate, so the paired finder
// hands crypto/tls the issuers above it as well.
func TestFindAllPairedCertificatesReturnsChain(t *testing.T) {
	skipTest(t, skipTestCert)

	withContext(t, func(ctx *Context) {
		chain := generateCertChain(t, "paired-leaf", "paired-intermediate", "paired-root")

		// The leaf is paired with the private key by CKA_ID. The issuers above it share no id
		// with the key and can only be reached by the chain walk.
		id := randomBytes()
		key, err := ctx.GenerateECDSAKeyPair(id, elliptic.P256())
		require.NoError(t, err)
		defer func() {
			assert.NoError(t, key.Delete())
		}()

		require.NoError(t, ctx.ImportCertificate(id, chain[0].cert))
		issuerIDs := importChain(t, ctx, chain[1:])
		defer deleteCerts(t, ctx, [][]byte{id}, issuerIDs)

		found, err := ctx.FindAllPairedCertificates()
		require.NoError(t, err)

		// The token may hold key pairs this test did not create, so the entry is picked out by
		// its leaf rather than by position.
		var got *tls.Certificate
		for i := range found {
			if found[i].Leaf != nil && bytes.Equal(found[i].Leaf.Raw, chain[0].cert.Raw) {
				got = &found[i]
				break
			}
		}
		require.NotNil(t, got, "the paired leaf was not returned")

		require.Len(t, got.Certificate, len(chain))
		for i, link := range chain {
			assert.Equal(t, link.cert.Raw, got.Certificate[i], "chain position %d", i)
		}
	})
}

// createCert signs template with the issuer's key and returns the parsed result.
func createCert(t *testing.T, template, parent *x509.Certificate,
	pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
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

// generateFastCert returns a self-signed ECDSA certificate with the given serial number. Tests
// that import more than a handful of certificates use this rather than generateRandomCert:
// nothing in them depends on the certificate being RSA, and an RSA-4096 key takes seconds to
// generate where a P-256 key takes microseconds.
func generateFastCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "find-all-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
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
