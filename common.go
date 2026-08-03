// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"encoding/asn1"
	"math/big"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/pkg/errors"
)

// CK_ULONG conversions live in the pkcs11-go binding, as pkcs11.ULongToBytes
// and pkcs11.BytesToULong. Its width is a property of the C ABI — 8 bytes under
// LP64, 4 under Windows' LLP64 model — so it belongs in the one package that
// holds the PKCS#11 headers. Keeping a copy here meant importing "C" for a
// single constant, and getting it wrong on Windows.

// Representation of a *DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// Populate a dsaSignature from a raw byte sequence
func (sig *dsaSignature) unmarshalBytes(sigBytes []byte) error {
	if len(sigBytes) == 0 || len(sigBytes)%2 != 0 {
		return errors.New("DSA signature length is invalid from token")
	}
	n := len(sigBytes) / 2
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(sigBytes[:n])
	sig.S.SetBytes(sigBytes[n:])
	return nil
}

// Populate a dsaSignature from DER encoding
func (sig *dsaSignature) unmarshalDER(sigDER []byte) error {
	if rest, err := asn1.Unmarshal(sigDER, sig); err != nil {
		return errors.WithMessage(err, "DSA signature contains invalid ASN.1 data")
	} else if len(rest) > 0 {
		return errors.New("unexpected data found after DSA signature")
	}
	return nil
}

// Return the DER encoding of a dsaSignature
func (sig *dsaSignature) marshalDER() ([]byte, error) {
	return asn1.Marshal(*sig)
}

// Compute *DSA signature and marshal the result in DER form
func (c *Context) dsaGeneric(key pkcs11.ObjectHandle, mechanism uint, digest []byte) ([]byte, error) {
	var err error
	var sigBytes []byte
	var sig dsaSignature
	mech := pkcs11.NewMechanism(mechanism, nil)
	err = c.withSession(func(session *pkcs11Session) error {
		if err = c.ctx.SignInit(session.handle, mech, key); err != nil {
			return err
		}
		sigBytes, err = c.ctx.Sign(session.handle, digest)
		return err
	})
	if err != nil {
		return nil, err
	}
	err = sig.unmarshalBytes(sigBytes)
	if err != nil {
		return nil, err
	}

	return sig.marshalDER()
}
