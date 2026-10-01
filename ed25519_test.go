// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ed448OID = mustMarshal(asn1.ObjectIdentifier{1, 3, 101, 113})

func ed25519Context(t *testing.T) *Context {
	t.Helper()
	ctx := testContext(t)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EDDSA)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN)
	return ctx
}

func TestHardEd25519(t *testing.T) {
	ctx := ed25519Context(t)

	id := randomBytes()
	label := randomBytes()

	key, err := ctx.GenerateEd25519KeyPairWithLabel(id, label)
	require.NoError(t, err)
	require.NotNil(t, key)
	defer func() { _ = key.Delete() }()

	pub, ok := key.Public().(ed25519.PublicKey)
	require.True(t, ok, "expected ed25519.PublicKey, got %T", key.Public())
	require.Len(t, pub, ed25519.PublicKeySize)

	testEd25519Signing(t, key, pub)

	key2, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)
	require.IsType(t, &pkcs11PrivateKeyEd25519{}, key2)
	assert.Equal(t, pub, key2.Public(), "the key found by id must export the same public key")
	testEd25519Signing(t, key2, pub)

	key3, err := ctx.FindKeyPair(nil, label)
	require.NoError(t, err)
	testEd25519Signing(t, key3, pub)

	priv, err := ctx.FindPrivateKey(id, nil)
	require.NoError(t, err)
	assert.Equal(t, uint(pkcs11.CKK_EC_EDWARDS), priv.KeyType())
	sig, err := priv.Sign(rand.Reader, []byte("private half only"), crypto.Hash(0))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, []byte("private half only"), sig))

	large := make([]byte, 64*1024)
	_, err = rand.Read(large)
	require.NoError(t, err)
	sig, err = key.Sign(rand.Reader, large, crypto.Hash(0))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, large, sig))
}

func testEd25519Signing(t *testing.T, key crypto.Signer, pub ed25519.PublicKey) {
	t.Helper()

	message := []byte("sign me with Ed25519")

	for name, opts := range map[string]crypto.SignerOpts{
		"nil":             nil,
		"crypto.Hash(0)":  crypto.Hash(0),
		"ed25519.Options": &ed25519.Options{},
	} {
		sig, err := key.Sign(rand.Reader, message, opts)
		require.NoError(t, err, "opts %s", name)
		require.Len(t, sig, ed25519.SignatureSize, "opts %s", name)
		assert.True(t, ed25519.Verify(pub, message, sig), "opts %s: signature failed to verify", name)
	}
}

func TestEd25519SignRejectsPrehashedAndContext(t *testing.T) {
	// A zero-value key: unsupported options must be rejected before any token access.
	key := &pkcs11PrivateKeyEd25519{}
	for name, opts := range map[string]crypto.SignerOpts{
		"SHA512":     crypto.SHA512,
		"Ed25519ph":  &ed25519.Options{Hash: crypto.SHA512},
		"Ed25519ctx": &ed25519.Options{Context: "crypto11 test"},
		"SHA256":     crypto.SHA256,
	} {
		t.Run(name, func(t *testing.T) {
			sig, err := key.Sign(nil, make([]byte, 64), opts)
			require.ErrorIs(t, err, errUnsupportedEdDSAOptions)
			assert.Nil(t, sig)
		})
	}
}

func TestEd25519EmptyMessage(t *testing.T) {
	// MaxSessions = 2: the next Sign reuses the session, exposing an operation left active.
	cfg := testConfig(t)
	cfg.MaxSessions = 2
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EDDSA)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN)

	key, err := ctx.GenerateEd25519KeyPair(randomBytes())
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()
	pub := key.Public().(ed25519.PublicKey)
	for name, message := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			sig, err := key.Sign(nil, message, crypto.Hash(0))
			require.ErrorIs(t, err, errEmptyMessage)
			assert.Nil(t, sig)

			next := []byte("sign after an empty message")
			sig, err = key.Sign(nil, next, crypto.Hash(0))
			if assert.NoError(t, err, "the session must remain usable") {
				assert.True(t, ed25519.Verify(pub, next, sig))
			}
		})
	}
}

func TestEd25519ConcurrentSign(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSessions = 4
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EDDSA)
	skipIfMechUnsupported(t, ctx, pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN)

	key, err := ctx.GenerateEd25519KeyPair(randomBytes())
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()
	pub := key.Public().(ed25519.PublicKey)
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			for n := range 50 {
				message := []byte(fmt.Sprintf("worker %d, message %d", worker, n))
				sig, err := key.Sign(nil, message, crypto.Hash(0))
				if !assert.NoError(t, err) {
					return
				}
				if !assert.True(t, ed25519.Verify(pub, message, sig)) {
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestEd25519Attributes(t *testing.T) {
	ctx := ed25519Context(t)

	key, err := ctx.GenerateEd25519KeyPair(randomBytes())
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	attrs, err := ctx.GetAttributes(key, []AttributeType{CkaKeyType, CkaEcParams})
	require.NoError(t, err)
	assert.Equal(t, uint(pkcs11.CKK_EC_EDWARDS), pkcs11.BytesToULong(attrs[CkaKeyType].Value))
	// SoftHSM2 stores it as the curve name, not the OID.
	assert.True(t, isEd25519Params(attrs[CkaEcParams].Value), "CKA_EC_PARAMS %x", attrs[CkaEcParams].Value)

	pubAttrs, err := ctx.GetPubAttributes(key, []AttributeType{CkaEcPoint})
	require.NoError(t, err)
	point, err := unmarshalEd25519Point(pubAttrs[CkaEcPoint].Value)
	require.NoError(t, err)
	assert.Equal(t, key.Public(), point)
}

func TestEd25519X509(t *testing.T) {
	ctx := ed25519Context(t)

	key, err := ctx.GenerateEd25519KeyPair(randomBytes())
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crypto11 Ed25519"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, x509.PureEd25519, cert.SignatureAlgorithm)
	assert.Equal(t, key.Public(), cert.PublicKey)
	require.NoError(t, cert.CheckSignatureFrom(cert))
}

func TestEd25519PairedThroughCertificate(t *testing.T) {
	skipTest(t, skipTestCert)
	ctx := ed25519Context(t)

	id := randomBytes()
	key, err := ctx.GenerateEd25519KeyPair(id)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "crypto11 Ed25519"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.NoError(t, ctx.ImportCertificate(id, cert))
	defer func() { _ = ctx.DeleteCertificate(id, nil, nil) }()

	k := key.(*pkcs11PrivateKeyEd25519)
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		return session.ctx.DestroyObject(session.handle, k.pubKeyHandle)
	}))
	k.pubKeyHandle = pkcs11.CK_INVALID_HANDLE

	found, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)
	assert.Equal(t, key.Public(), found.Public())
	testEd25519Signing(t, found, found.Public().(ed25519.PublicKey))
}

func TestEd25519RequiredArgs(t *testing.T) {
	ctx := testContext(t)

	_, err := ctx.GenerateEd25519KeyPair(nil)
	require.Error(t, err)

	val := randomBytes()

	_, err = ctx.GenerateEd25519KeyPairWithLabel(nil, val)
	require.Error(t, err)

	_, err = ctx.GenerateEd25519KeyPairWithLabel(val, nil)
	require.Error(t, err)
}

func TestEd25519TemplateCurveName(t *testing.T) {
	ctx := ed25519Context(t)

	id := randomBytes()
	public, err := NewAttributeSetWithID(id)
	require.NoError(t, err)
	require.NoError(t, public.Set(CkaEcParams, ed25519CurveName))
	private, err := NewAttributeSetWithID(id)
	require.NoError(t, err)

	key, err := ctx.GenerateEd25519KeyPairWithAttributes(public, private)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	found, err := ctx.FindKeyPair(id, nil)
	require.NoError(t, err)
	assert.Equal(t, key.Public(), found.Public())
	testEd25519Signing(t, found, found.Public().(ed25519.PublicKey))
}

func TestEd25519RejectsEd448TemplateBeforeGeneration(t *testing.T) {
	ctx := ed25519Context(t)

	id := randomBytes()
	public, err := NewAttributeSetWithID(id)
	require.NoError(t, err)
	require.NoError(t, public.Set(CkaEcParams, ed448OID))
	private, err := NewAttributeSetWithID(id)
	require.NoError(t, err)

	_, err = ctx.GenerateEd25519KeyPairWithAttributes(public, private)
	require.ErrorIs(t, err, errUnsupportedEllipticCurve)
	assert.Equal(t, 0, countObjectsWithID(t, ctx, id))
}

func generateEd448KeyPair(t *testing.T, ctx *Context, id []byte) (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
	t.Helper()
	var pubHandle, privHandle pkcs11.ObjectHandle
	err := ctx.withSession(func(session *pkcs11Session) (err error) {
		pubHandle, privHandle, err = session.ctx.GenerateKeyPair(session.handle,
			pkcs11.NewMechanism(pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN, nil),
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
				pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed448OID),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			},
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			})
		return err
	})
	if errors.Is(err, pkcs11.Error(pkcs11.CKR_CURVE_NOT_SUPPORTED)) ||
		errors.Is(err, pkcs11.Error(pkcs11.CKR_DOMAIN_PARAMS_INVALID)) {
		t.Skipf("token cannot generate an Ed448 key pair: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
			for _, handle := range []pkcs11.ObjectHandle{privHandle, pubHandle} {
				err := session.ctx.DestroyObject(session.handle, handle)
				if err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)) {
					return err
				}
			}
			return nil
		}))
	})
	return pubHandle, privHandle
}

func TestEd25519EnumerationSkipsEd448(t *testing.T) {
	ctx := ed25519Context(t)
	id := randomBytes()
	generateEd448KeyPair(t, ctx, id)

	pairs, err := ctx.FindKeyPairs(id, nil)
	require.NoError(t, err)
	assert.Empty(t, pairs)

	_, err = ctx.FindAllKeyPairs()
	require.NoError(t, err)

	privs, err := ctx.FindPrivateKeys(id, nil)
	require.NoError(t, err)
	assert.Empty(t, privs)
}

func TestEd25519EnumerationSkipsEd448WithEd25519Certificate(t *testing.T) {
	skipTest(t, skipTestCert)
	ctx := ed25519Context(t)
	id := randomBytes()
	pubHandle, _ := generateEd448KeyPair(t, ctx, id)
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		return session.ctx.DestroyObject(session.handle, pubHandle)
	}))

	pub, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unrelated Ed25519 certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.NoError(t, ctx.ImportCertificate(id, cert))
	defer func() { _ = ctx.DeleteCertificate(id, nil, nil) }()

	pairs, err := ctx.FindKeyPairs(id, nil)
	require.NoError(t, err)
	assert.Empty(t, pairs, "an Ed25519 certificate cannot turn an Ed448 private key into Ed25519")
	privs, err := ctx.FindPrivateKeys(id, nil)
	require.NoError(t, err)
	assert.Empty(t, privs)
}

func TestEd25519EnumerationSkipsEd448WithEd25519PublicKey(t *testing.T) {
	ctx := ed25519Context(t)
	id := randomBytes()
	pubHandle, _ := generateEd448KeyPair(t, ctx, id)
	require.NoError(t, ctx.withSession(func(session *pkcs11Session) error {
		return session.ctx.DestroyObject(session.handle, pubHandle)
	}))

	key, err := ctx.GenerateEd25519KeyPair(id)
	require.NoError(t, err)
	defer func() { _ = key.Delete() }()

	pairs, err := ctx.FindKeyPairs(id, nil)
	require.NoError(t, err)
	require.Len(t, pairs, 1, "only the actual Ed25519 private key may be returned")
	testEd25519Signing(t, pairs[0], key.Public().(ed25519.PublicKey))
	privs, err := ctx.FindPrivateKeys(id, nil)
	require.NoError(t, err)
	assert.Len(t, privs, 1)
}

func TestUnmarshalEd25519Point(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrapped, err := asn1.Marshal([]byte(pub))
	require.NoError(t, err)

	// Also a valid OCTET STRING of 30 bytes; at 32 bytes total it is a bare point.
	ambiguous := append([]byte{0x04, 0x1e}, make([]byte, 30)...)
	for name, tc := range map[string]struct{ input, want []byte }{
		"DER OCTET STRING": {wrapped, pub},
		"bare point":       {pub, pub},
		"bare ASN.1":       {ambiguous, ambiguous},
	} {
		t.Run(name, func(t *testing.T) {
			input := bytes.Clone(tc.input)
			got, err := unmarshalEd25519Point(input)
			require.NoError(t, err)
			assert.Equal(t, ed25519.PublicKey(tc.want), got)
			got[0] ^= 0xff
			assert.Equal(t, tc.input, input, "the public key must not alias the attribute buffer")
		})
	}

	for name, in := range map[string][]byte{
		"empty":                {},
		"nil":                  nil,
		"short bare":           make([]byte, 31),
		"long bare":            make([]byte, 33),
		"wrapped, 31 inside":   mustMarshal(make([]byte, 31)),
		"wrapped, 33 inside":   mustMarshal(make([]byte, 33)),
		"trailing data":        append(bytes.Clone(wrapped), 0),
		"truncated":            wrapped[:len(wrapped)-1],
		"not an OCTET STRING":  mustMarshal(asn1.ObjectIdentifier{1, 3, 101, 112}),
		"Ed448-sized, wrapped": mustMarshal(make([]byte, 57)),
		"wrong tag":            append([]byte{0x03, 0x20}, make([]byte, 32)...),
		"wrong length header":  append([]byte{0x04, 0x1f}, make([]byte, 32)...),
		"non-minimal length":   append([]byte{0x04, 0x81, 0x20}, make([]byte, 32)...),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := unmarshalEd25519Point(in)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

func BenchmarkUnmarshalEd25519Point(b *testing.B) {
	point := make([]byte, ed25519.PublicKeySize)
	for name, input := range map[string][]byte{
		"bare": point,
		"DER":  mustMarshal(point),
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := unmarshalEd25519Point(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestIsEd25519Params(t *testing.T) {
	assert.True(t, isEd25519Params(ed25519OID))
	assert.True(t, isEd25519Params(ed25519CurveName))
	assert.False(t, isEd25519Params(ed448OID))
	assert.False(t, isEd25519Params(mustMarshal("Ed25519")))
	assert.False(t, isEd25519Params(nil))
}
