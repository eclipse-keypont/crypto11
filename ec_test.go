package crypto11

import (
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

var ecdhCurves = []ecdh.Curve{
	ecdh.P256(),
	ecdh.P384(),
	ecdh.P521(),
	// plus something with explicit parameters
}

func TestEcDerive(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

	id := randomBytes()
	label := randomBytes()

	for _, curve := range ecdhCurves {
		c, ok := wellKnownCurves[fmt.Sprintf("%s", curve)]
		if !ok {
			t.Errorf("unsupported curve: %s", curve)
			return
		}

		key, err := ctx.GenerateECKeyPairWithLabel(id, label, c.curve, ECDH)
		require.NoError(t, err)
		hsmKey, ok := key.(Deriver)
		if !ok {
			require.Fail(t, "key does not implement crypto.Deriver")
			return
		}
		defer func(k Deriver) { _ = k.Delete() }(hsmKey)

		nativeKey, err := curve.GenerateKey(rand.Reader)
		require.NoError(t, err)

		testSymmetricCiphes := []*SymmetricCipher{CipherGeneric}
		// only P-256 can be used with AES when KDF is CKD_NULL, because the shared secret is 32 bytes long, which is the key size for AES-256
		if c.curve.Params().Name == "P-256" {
			testSymmetricCiphes = append(testSymmetricCiphes, CipherAES)
		}

		for _, cipher := range testSymmetricCiphes {
			template := NewAttributeSet()
			template.AddIfNotPresent([]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
			})

			secret, err := hsmKey.Derive(template, cipher, &pkcs11.ECDH1DeriveParams{
				KDF:           pkcs11.CKD_NULL,
				PublicKeyData: nativeKey.Public().(*ecdh.PublicKey).Bytes(),
			})
			require.NoError(t, err)
			shared1, err := getSharedSecretValue(secret)
			require.NoError(t, err)

			shared2, err := nativeKey.ECDH(hsmKey.Public().(*ecdh.PublicKey))
			require.NoError(t, err)

			require.Equal(t, shared1, shared2)
		}
	}
}

func getSharedSecretValue(secret *SecretKey) ([]byte, error) {
	var buf []byte
	err := secret.context.withSession(func(session *pkcs11Session) error {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		}
		attr, err := session.ctx.GetAttributeValue(session.handle, secret.handle, template)
		if err != nil {
			return err
		}
		buf = attr[0].Value
		return nil
	})
	return buf, err
}

func TestEcSigning(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		err = ctx.Close()
		require.NoError(t, err)
	}()

	for _, curve := range curves {
		id := randomBytes()
		label := randomBytes()

		key, err := ctx.GenerateECKeyPairWithLabel(id, label, curve, ECDSA)
		require.NoError(t, err)
		require.NotNil(t, key)
		signer, ok := key.(Signer)
		if !ok {
			require.Fail(t, "key does not implement crypto.Signer")
			return
		}
		defer func(k Signer) { _ = k.Delete() }(signer)

		testEcdsaSigning(t, signer, crypto.SHA1, curve.Params().Name, "SHA-1")
		testEcdsaSigning(t, signer, crypto.SHA224, curve.Params().Name, "SHA-224")
		testEcdsaSigning(t, signer, crypto.SHA256, curve.Params().Name, "SHA-256")
		testEcdsaSigning(t, signer, crypto.SHA384, curve.Params().Name, "SHA-384")
		testEcdsaSigning(t, signer, crypto.SHA512, curve.Params().Name, "SHA-512")

		key2, err := ctx.FindKeyPair(id, nil)
		require.NoError(t, err)
		testEcdsaSigning(t, key2.(*pkcs11PrivateKeyEC), crypto.SHA256, curve.Params().Name, "SHA-256")

		key3, err := ctx.FindKeyPair(nil, label)
		require.NoError(t, err)
		testEcdsaSigning(t, key3.(crypto.Signer), crypto.SHA384, curve.Params().Name, "SHA-384")
	}
}

func TestECRequiredArgs(t *testing.T) {
	ctx, err := ConfigureFromFile("config")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	_, err = ctx.GenerateECKeyPair(nil, elliptic.P224(), ECDSA)
	require.Error(t, err)

	id := randomBytes()

	_, err = ctx.GenerateECKeyPair(id, elliptic.P224(), nil)
	require.Error(t, err)

	val := randomBytes()

	_, err = ctx.GenerateECKeyPairWithLabel(nil, val, elliptic.P224(), ECDSA)
	require.Error(t, err)

	_, err = ctx.GenerateECKeyPairWithLabel(val, nil, elliptic.P224(), ECDSA)
	require.Error(t, err)
}

func TestECDHDeriveRequiredArgs(t *testing.T) {
	key := &pkcs11PrivateKeyEC{
		pkcs11PrivateKey: pkcs11PrivateKey{
			pkcs11Object: pkcs11Object{
				context: &Context{},
			},
		},
	}

	_, err := key.Derive(NewAttributeSet(), &SymmetricCipher{}, nil)
	require.Error(t, err)

	_, err = key.Derive(NewAttributeSet(), nil, nil)
	require.Error(t, err)

	_, err = key.Derive(NewAttributeSet(), CipherGeneric, nil)
	require.Error(t, err)
}

func TestRegisterECDH1CustomKDF(t *testing.T) {
	const CKD_CUSTOM_SHA256_KDF = pkcs11.CKO_VENDOR_DEFINED | pkcs11.CKD_SHA256_KDF

	err := RegisterECDH1CustomKDF(CKD_CUSTOM_SHA256_KDF, 32)
	require.NoError(t, err)

	// registering the same KDF again should fail
	err = RegisterECDH1CustomKDF(CKD_CUSTOM_SHA256_KDF, 32)
	require.Error(t, err)
}
