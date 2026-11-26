//go:build !go1.27

package crypto11

import (
	"crypto"
	"fmt"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

func makeMLDSAKeyPair(*pkcs11Session, *pkcs11PrivateKey, *pkcs11.ObjectHandle, crypto.PublicKey) (Signer, error) {
	return nil, fmt.Errorf("%w: %X", errUnsupportedKeyType, pkcs11.CKK_ML_DSA)
}

func exportMLDSAPublicKey(session *pkcs11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("%w: %X", errUnsupportedKeyType, pkcs11.CKK_ML_DSA)
}
