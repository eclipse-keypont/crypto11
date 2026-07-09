// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
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

type genericAead struct {
	key *SecretKey

	overhead int

	nonceSize int

	// Note - if the GCMParams result is non-nil, the caller must call Free() on the params when
	// finished.
	makeMech func(nonce []byte, additionalData []byte, encrypt bool) (*pkcs11.Mechanism, *pkcs11.GCMParams, error)
}

// NewGCM returns a given cipher wrapped in Galois Counter Mode, with the standard
// nonce length.
//
// This depends on the HSM supporting the CKM_*_GCM mechanism. If it is not supported
// then you must use cipher.NewGCM; it will be slow.
func (key *SecretKey) NewGCM() (cipher.AEAD, error) {
	if key.Cipher.GCMMech == 0 {
		return nil, fmt.Errorf("GCM not implemented for key type %#x", key.Cipher.GenParams[0].KeyType)
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

func (g genericAead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {

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
		if result, err = session.ctx.Encrypt(session.handle, plaintext); err != nil {
			err = fmt.Errorf("C_Encrypt: %w", err)
			return
		}

		// When the token generates its own GCM IV (UseGCMIVFromHSM), the actual
		// IV used is written by the token into the CK_GCM_PARAMS buffer. We MUST
		// copy it back into the caller's nonce slice, otherwise the caller never
		// learns the IV and the ciphertext cannot be decrypted — or, worse, the
		// caller assumes a zero/garbage nonce was used, risking catastrophic GCM
		// nonce reuse. This must happen whenever UseGCMIVFromHSM is set,
		// independently of the SupplyIvForHSMGCMEncrypt buffer-management flag.
		if g.key.context.cfg.UseGCMIVFromHSM {
			hsmIV := params.IV()
			if len(nonce) != len(hsmIV) {
				return errBadGCMNonceSize
			}
			copy(nonce, hsmIV)
		}

		return
	}); err != nil {
		panic(err)
	}
	dst = append(dst, result...)
	return dst
}

func (g genericAead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
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
		if result, err = session.ctx.Decrypt(session.handle, ciphertext); err != nil {
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
