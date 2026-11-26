// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// cipher.AEAD ----------------------------------------------------------

// A PaddingMode is used by a block cipher (see NewCBC).
type PaddingMode int

const (
	// PaddingNone represents a block cipher with no padding.
	PaddingNone PaddingMode = iota

	// PaddingPKCS represents a block cipher used with PKCS#7 padding.
	PaddingPKCS
)

var errBadGCMNonceSize = errors.New("nonce slice too small to hold IV")

// errGCMNonceLength is the panic value of Seal, and the error from Open, when the nonce is not
// NonceSize() bytes long. A nonce of another length, an empty one especially, is usually a
// constant, and GCM under a repeated IV gives away both the plaintext and the ability to forge.
var errGCMNonceLength = errors.New("crypto11: incorrect nonce length given to GCM")

// errGCMIVNotGenerated is the panic value of Seal when Config.UseGCMIVFromHSM is set but the token
// did not generate the IV. Every message would then be encrypted under the same IV.
var errGCMIVNotGenerated = errors.New("crypto11: UseGCMIVFromHSM is set but the token did not generate a GCM IV")

// minGCMNonceSize is the shortest GCM IV NewGCM accepts: 96 bits, as NIST SP 800-38D recommends.
const minGCMNonceSize = 12

type genericAead struct {
	key *SecretKey

	overhead int

	nonceSize int

	// Note - if the GCMParams result is non-nil, the caller must call Free() on the params when
	// finished.
	makeMech func(nonce []byte, additionalData []byte, encrypt bool) (*pkcs11.Mechanism, *pkcs11.GCMParams, error)
}

// NewGCM returns a given cipher wrapped in Galois Counter Mode, with the nonce length set by
// Config.GCMIVLength.
//
// As with crypto/cipher, Seal panics and Open fails unless the nonce is NonceSize() bytes long,
// and a nonce must never be used twice with the same key. With Config.UseGCMIVFromHSM the token
// generates the IV instead; see that field for what Seal then expects.
//
// This depends on the HSM supporting the CKM_*_GCM mechanism. If it is not supported
// then you must use cipher.NewGCM; it will be slow.
func (key *SecretKey) NewGCM() (cipher.AEAD, error) {
	if key.Cipher.GCMMech == 0 {
		return nil, fmt.Errorf("GCM not implemented for key type %#x", key.Cipher.GenParams[0].KeyType)
	}
	if n := key.context.cfg.GCMIVLength; n < minGCMNonceSize {
		return nil, fmt.Errorf("GCMIVLength %d is too short: GCM IVs must be at least %d bytes", n, minGCMNonceSize)
	}

	g := genericAead{
		key:       key,
		overhead:  16,
		nonceSize: key.context.cfg.GCMIVLength,
		makeMech: func(nonce []byte, additionalData []byte, encrypt bool) (*pkcs11.Mechanism, *pkcs11.GCMParams, error) {
			var params *pkcs11.GCMParams

			if (encrypt && key.context.cfg.UseGCMIVFromHSM &&
				!key.context.cfg.GCMIVFromHSMControl.SupplyIvForHSMGCMEncrypt) || (!encrypt &&
				key.context.cfg.UseGCMIVFromHSM && !key.context.cfg.GCMIVFromHSMControl.SupplyIvForHSMGCMDecrypt) {
				params = pkcs11.NewGCMParams(nil, additionalData, 16*8 /*bits*/)
			} else {
				params = pkcs11.NewGCMParams(nonce, additionalData, 16*8 /*bits*/)
			}
			return pkcs11.NewMechanismWithParams(key.Cipher.GCMMech, params), params, nil
		},
	}
	return g, nil
}

func (g genericAead) NonceSize() int {
	return g.nonceSize
}

func (g genericAead) Overhead() int {
	return g.overhead
}

// ivSupplied reports whether the IV goes to the token in CK_GCM_PARAMS. It does unless the token
// generates the IV and was configured to be given no IV buffer.
func (g genericAead) ivSupplied(encrypt bool) bool {
	cfg := g.key.context.cfg
	if !cfg.UseGCMIVFromHSM {
		return true
	}
	if encrypt {
		return cfg.GCMIVFromHSMControl.SupplyIvForHSMGCMEncrypt
	}
	return cfg.GCMIVFromHSMControl.SupplyIvForHSMGCMDecrypt
}

func (g genericAead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	hsmIV := g.key.context.cfg.UseGCMIVFromHSM
	supplied := g.ivSupplied(true)
	// Without an IV buffer the nonce is not sent at all: the token generates the IV and appends
	// it to the ciphertext. An empty nonce or one of the usual size is accepted for that case.
	if len(nonce) != g.nonceSize && (supplied || len(nonce) != 0) {
		panic(errGCMNonceLength)
	}

	var result []byte
	if err := g.key.context.withSession(func(session *pkcs11Session) (err error) {
		mech, params, err := g.makeMech(nonce, additionalData, true)

		if err != nil {
			return err
		}
		defer params.Free()

		if err = session.ctx.EncryptInit(session.handle, mech, g.key.handle); err != nil {
			err = fmt.Errorf("C_EncryptInit: %w", err)
			return
		}
		if result, err = opResult(session.ctx.Encrypt(session.handle, plaintext)); err != nil {
			err = fmt.Errorf("C_Encrypt: %w", err)
			return
		}

		// When the token generates its own GCM IV (UseGCMIVFromHSM), make sure it did, since
		// otherwise every message goes out under the same IV:
		//   - given an IV buffer, the token writes the IV it used into it, and the IV is copied
		//     back into the caller's nonce slice so the caller can decrypt. A buffer the token
		//     left as it was means it used the caller's bytes rather than a fresh IV;
		//   - given none, the token appends the IV to the ciphertext and tag. Output without it
		//     was encrypted under an empty IV.
		if hsmIV {
			if supplied {
				iv := params.IV()
				if len(nonce) != len(iv) {
					return errBadGCMNonceSize
				}
				if bytes.Equal(iv, nonce) {
					return errGCMIVNotGenerated
				}
				copy(nonce, iv)
			} else if len(result) != len(plaintext)+g.overhead+g.nonceSize {
				return errGCMIVNotGenerated
			}
		}

		return
	}); err != nil {
		panic(err)
	}
	dst = append(dst, result...)
	return dst
}

func (g genericAead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if g.ivSupplied(false) && len(nonce) != g.nonceSize {
		return nil, errGCMNonceLength
	}
	var result []byte
	if err := g.key.context.withSession(func(session *pkcs11Session) (err error) {
		mech, params, err := g.makeMech(nonce, additionalData, false)
		if err != nil {
			return
		}
		defer params.Free()

		if err = session.ctx.DecryptInit(session.handle, mech, g.key.handle); err != nil {
			err = fmt.Errorf("C_DecryptInit: %w", err)
			return
		}
		if result, err = opResult(session.ctx.Decrypt(session.handle, ciphertext)); err != nil {
			err = fmt.Errorf("C_Decrypt: %w", err)
			return
		}
		return
	}); err != nil {
		return nil, err
	}
	dst = append(dst, result...)
	return dst, nil
}
