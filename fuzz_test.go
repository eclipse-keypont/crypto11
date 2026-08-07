// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

// Fuzz targets for the parts of crypto11 that turn bytes into values.
//
// Almost everything in this package needs a live token and is therefore out of reach of
// go test -fuzz, which requires targets that are pure, fast and deterministic. What is left
// is not incidental: every byte slice these functions parse arrives from the token, via
// C_GetAttributeValue or C_Sign, and token contents are not necessarily under the caller's
// control — anything able to write to the token decides what CKA_VALUE or CKA_EC_POINT
// holds. That is the trust boundary these targets sit on.
//
// Seed inputs are supplied with f.Add. The testdata/fuzz directory is reserved for the
// inputs the fuzzing engine writes when a target fails: commit those as regression cases,
// where `go test ./...` replays them on every run.
//
// Run one target locally:
//
//	go test -run '^$' -fuzz '^FuzzParseCertificateValue$' -fuzztime 60s .
//
// No PKCS#11 module is needed — see TestMain in setup_test.go.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// ── Certificate parsing ──────────────────────────────────────────────────────

// FuzzParseCertificateValue exercises the hand-rolled DER framing in parseCertificateValue,
// which delimits a certificate by its own ASN.1 length so that a token's null padding of
// CKA_VALUE is not mistaken for trailing data (and a certificate legitimately ending in a
// zero byte is not truncated).
func FuzzParseCertificateValue(f *testing.F) {
	der := seedCertificate(f)

	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x00})             // empty SEQUENCE
	f.Add([]byte{0x30, 0x82, 0xff, 0xff}) // length far beyond the buffer
	f.Add(der)
	f.Add(append(append([]byte(nil), der...), 0, 0, 0, 0)) // null-padded, as a token pads the attribute
	f.Add(append(append([]byte(nil), der...), 0, 0, 1))    // trailing data that is not padding
	f.Add(der[:len(der)/2])                                // truncated mid-certificate

	f.Fuzz(func(t *testing.T, raw []byte) {
		cert, err := parseCertificateValue(raw)
		if err != nil {
			if cert != nil {
				t.Fatalf("certificate returned alongside an error: %v", err)
			}
			return
		}

		if cert == nil {
			t.Fatal("nil certificate returned without an error")
		}

		// Whatever was parsed has to be a genuine prefix of the input: the framing must
		// never hand x509 bytes it invented, nor drop bytes the token supplied.
		if !bytes.HasPrefix(raw, cert.Raw) {
			t.Fatalf("parsed certificate (%d bytes) is not a prefix of the input (%d bytes)",
				len(cert.Raw), len(raw))
		}

		// And everything past it must have been padding, or it should have been rejected.
		for i, b := range raw[len(cert.Raw):] {
			if b != 0 {
				t.Fatalf("accepted %d trailing bytes, offset %d is %#x, not null",
					len(raw)-len(cert.Raw), i, b)
			}
		}
	})
}

// ── Elliptic curve points and parameters ─────────────────────────────────────

// fuzzCurves are the curves crypto11 can export a public key for, in a fixed order: a fuzz
// input selects one by index, and map iteration order would not be reproducible.
var fuzzCurves = []elliptic.Curve{
	elliptic.P224(),
	elliptic.P256(),
	elliptic.P384(),
	elliptic.P521(),
}

// FuzzUnmarshalEcPoint exercises the CKA_EC_POINT path used by exportECDSAPublicKey. The
// ASN.1 wrapper and the point encoding inside it both come off the token, and the point
// decoding underneath is crypto/elliptic's deprecated Unmarshal.
func FuzzUnmarshalEcPoint(f *testing.F) {
	for i, curve := range fuzzCurves {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			f.Fatalf("generating a %s seed key: %v", curve.Params().Name, err)
		}

		point := uncompressedPoint(curve, key.X, key.Y)
		wrapped, err := asn1.Marshal(point)
		if err != nil {
			f.Fatalf("marshalling a %s seed point: %v", curve.Params().Name, err)
		}

		f.Add(uint8(i), wrapped)
		f.Add(uint8(i), point)                    // the bare point, without its OCTET STRING wrapper
		f.Add(uint8(i), wrapped[:len(wrapped)-1]) // truncated
	}

	f.Add(uint8(0), []byte(nil))
	f.Add(uint8(0), []byte{0x04, 0x00})

	f.Fuzz(func(t *testing.T, curveSel uint8, b []byte) {
		curve := fuzzCurves[int(curveSel)%len(fuzzCurves)]

		x, y, err := unmarshalEcPoint(b, curve)
		if err != nil {
			return
		}

		if x == nil || y == nil {
			t.Fatalf("nil coordinate returned without an error on %s", curve.Params().Name)
		}

		// An accepted point has to re-encode to exactly the bytes the token supplied.
		var point []byte
		if _, err := asn1.Unmarshal(b, &point); err != nil {
			t.Fatalf("point accepted but its ASN.1 wrapper no longer parses: %v", err)
		}
		if got := uncompressedPoint(curve, x, y); !bytes.Equal(got, point) {
			t.Fatalf("point does not round-trip on %s: got %x, want %x",
				curve.Params().Name, got, point)
		}
	})
}

// FuzzUnmarshalEcParams checks that the CKA_EC_PARAMS lookup only ever resolves to a curve
// crypto11 actually knows, whatever the token returns.
func FuzzUnmarshalEcParams(f *testing.F) {
	for _, info := range wellKnownCurves {
		f.Add(info.oid)
	}
	f.Add([]byte(nil))
	f.Add([]byte{0x06, 0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		curve, err := unmarshalEcParams(b)
		if err != nil {
			if curve != nil {
				t.Fatalf("curve returned alongside an error: %v", err)
			}
			return
		}

		if curve == nil {
			t.Fatal("nil curve returned without an error")
		}

		info, known := wellKnownCurves[curve.Params().Name]
		if !known || info.curve == nil {
			t.Fatalf("resolved to %q, which is not a supported curve", curve.Params().Name)
		}
		if !bytes.Equal(b, info.oid) {
			t.Fatalf("resolved %x to %q, whose OID is %x", b, curve.Params().Name, info.oid)
		}
	})
}

// ── DSA / ECDSA signature conversion ─────────────────────────────────────────

// FuzzDSASignatureRoundTrip drives the conversion dsaGeneric performs on every signature a
// token produces: the raw C_Sign output is split in half into (R, S) and re-encoded as DER.
// A signature the split accepts must survive the round trip unchanged.
func FuzzDSASignatureRoundTrip(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, 40))                          // DSA-sized, all zero
	f.Add(bytes.Repeat([]byte{0xff}, 64))            // P-256-sized, maximal
	f.Add(append(make([]byte, 31), 0x01))            // leading zeros in S
	f.Add(append([]byte{0x80}, make([]byte, 63)...)) // high bit set in R

	f.Fuzz(func(t *testing.T, raw []byte) {
		var sig dsaSignature
		if err := sig.unmarshalBytes(raw); err != nil {
			return
		}

		der, err := sig.marshalDER()
		if err != nil {
			t.Fatalf("marshalDER rejected a signature unmarshalBytes accepted: %v", err)
		}

		var back dsaSignature
		if err := back.unmarshalDER(der); err != nil {
			t.Fatalf("unmarshalDER rejected our own encoding: %v", err)
		}

		if sig.R.Cmp(back.R) != 0 || sig.S.Cmp(back.S) != 0 {
			t.Fatalf("round trip changed the signature: (%s, %s) became (%s, %s)",
				sig.R, sig.S, back.R, back.S)
		}
	})
}

// FuzzDSASignatureUnmarshalDER feeds arbitrary bytes to the DER decoder, which is what a
// caller reaches when verifying a signature this package produced.
func FuzzDSASignatureUnmarshalDER(f *testing.F) {
	valid, err := (&dsaSignature{R: big.NewInt(1), S: big.NewInt(2)}).marshalDER()
	if err != nil {
		f.Fatalf("building a seed signature: %v", err)
	}

	f.Add(valid)
	f.Add(append(append([]byte(nil), valid...), 0x00)) // trailing data
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, der []byte) {
		var sig dsaSignature
		if err := sig.unmarshalDER(der); err != nil {
			return
		}

		if sig.R == nil || sig.S == nil {
			t.Fatal("nil component returned without an error")
		}
	})
}

// ── ML-KEM key derivation ────────────────────────────────────────────────────

// mlkemFuzzParamSets is every parameter set MLKEMDeriveKey supports, in a fixed order.
var mlkemFuzzParamSets = []MLKEMParameterSet{MLKEM512, MLKEM768, MLKEM1024}

// FuzzMLKEMDeriveKey checks the properties the KDF has to hold whatever the shared secret
// looks like: the output is the size the parameter set calls for, derivation is
// deterministic, and two parameter sets never derive the same key from one secret — the
// domain separation that mixing mlkemAlgorithmID into the KMAC context exists to provide.
//
// Secret lengths around the KMAC rates (136 and 168 bytes) are seeded deliberately: that is
// where bytepad changes the number of blocks absorbed.
func FuzzMLKEMDeriveKey(f *testing.F) {
	for _, n := range []int{0, 1, 32, 135, 136, 137, 167, 168, 169, 1088} {
		f.Add(bytes.Repeat([]byte{0xa5}, n))
	}
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, secret []byte) {
		derived := make([][]byte, 0, len(mlkemFuzzParamSets))

		for _, paramSet := range mlkemFuzzParamSets {
			key, err := MLKEMDeriveKey(paramSet, secret)
			if err != nil {
				t.Fatalf("parameter set %d: %v", paramSet, err)
			}

			if want := mlkemCekSize[paramSet]; len(key) != want {
				t.Fatalf("parameter set %d derived %d bytes, want %d", paramSet, len(key), want)
			}

			again, err := MLKEMDeriveKey(paramSet, secret)
			if err != nil {
				t.Fatalf("parameter set %d, second derivation: %v", paramSet, err)
			}
			if !bytes.Equal(key, again) {
				t.Fatalf("parameter set %d is not deterministic", paramSet)
			}

			derived = append(derived, key)
		}

		for i := range derived {
			for j := i + 1; j < len(derived); j++ {
				if bytes.Equal(derived[i], derived[j]) {
					t.Fatalf("parameter sets %d and %d derived the same key from one secret",
						mlkemFuzzParamSets[i], mlkemFuzzParamSets[j])
				}
			}
		}
	})
}

// FuzzKMACEncodings checks the NIST SP 800-185 encoding primitives KMAC is built on. Both
// encodings carry their own length, so each one has to decode back to the value it was given,
// and the length byte has to agree with the bytes beside it — an off-by-one here changes
// every derived key silently rather than failing.
func FuzzKMACEncodings(f *testing.F) {
	for _, x := range []uint64{0, 1, 8, 255, 256, 65535, 65536, 1 << 32, 1<<64 - 1} {
		f.Add(x)
	}

	f.Fuzz(func(t *testing.T, x uint64) {
		left := leftEncode(x)
		if len(left) < 2 || len(left) > 9 {
			t.Fatalf("leftEncode(%d) is %d bytes: %x", x, len(left), left)
		}
		if int(left[0]) != len(left)-1 {
			t.Fatalf("leftEncode(%d) declares %d bytes but carries %d: %x",
				x, left[0], len(left)-1, left)
		}
		if got := beUint(left[1:]); got != x {
			t.Fatalf("leftEncode(%d) decodes back to %d: %x", x, got, left)
		}
		if x > 0 && left[1] == 0 {
			t.Fatalf("leftEncode(%d) is not minimal: %x", x, left)
		}

		right := rightEncode(x)
		if len(right) < 2 || len(right) > 9 {
			t.Fatalf("rightEncode(%d) is %d bytes: %x", x, len(right), right)
		}
		if int(right[len(right)-1]) != len(right)-1 {
			t.Fatalf("rightEncode(%d) declares %d bytes but carries %d: %x",
				x, right[len(right)-1], len(right)-1, right)
		}
		if got := beUint(right[:len(right)-1]); got != x {
			t.Fatalf("rightEncode(%d) decodes back to %d: %x", x, got, right)
		}
		if x > 0 && right[0] == 0 {
			t.Fatalf("rightEncode(%d) is not minimal: %x", x, right)
		}

		// bytepad, at the two rates kmac128 and kmac256 use, must produce whole blocks
		// prefixed with left_encode(w).
		for _, w := range []int{136, 168} {
			padded := bytepad(encodeString(left), w)
			if len(padded)%w != 0 {
				t.Fatalf("bytepad(..., %d) produced %d bytes", w, len(padded))
			}
			if !bytes.HasPrefix(padded, leftEncode(uint64(w))) {
				t.Fatalf("bytepad(..., %d) does not start with left_encode(%d): %x", w, w, padded)
			}
		}
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// seedCertificate returns the DER of a self-signed certificate, for use as a fuzz seed.
func seedCertificate(tb testing.TB) []byte {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating a seed key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crypto11 fuzz seed"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("creating a seed certificate: %v", err)
	}

	return der
}

// uncompressedPoint encodes (x, y) in the uncompressed form of SEC 1, section 2.3.3 — the
// form crypto/elliptic's Unmarshal accepts, spelled out here rather than calling its
// deprecated Marshal.
func uncompressedPoint(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8

	out := make([]byte, 1+2*byteLen)
	out[0] = 4
	x.FillBytes(out[1 : 1+byteLen])
	y.FillBytes(out[1+byteLen:])

	return out
}

// beUint decodes up to eight big-endian bytes.
func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}
