// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"fmt"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// defaultPrivate returns the CKA_PRIVATE value applied to the private and secret
// keys crypto11 generates when the caller's template does not set it.
//
// CKA_PRIVATE=true makes an object visible and usable only once a user has
// logged in. Left unset, its value is the token's default, and on a token that
// defaults it to false a party with access to the token but no PIN can use the
// key — for signing or decryption — without ever authenticating: CKA_SENSITIVE
// and CKA_EXTRACTABLE protect the key's value, not its use. So the default is
// true, with one exception: a Context configured with LoginNotSupported never
// logs in, and a private object created through it could not be reached by
// anyone, itself included.
//
// A caller that deliberately wants a public object passes CKA_PRIVATE=false in
// the template; AddIfNotPresent leaves an explicit value alone.
func (c *Context) defaultPrivate() bool {
	return !c.cfg.LoginNotSupported
}

// destroyKeyPair removes both halves of a key pair whose generation could not
// be completed: C_GenerateKeyPair succeeded, then a later step — exporting the
// public key, checking it against the request — failed with cause. Both objects
// default to CKA_TOKEN=true, so leaving them would consume persistent token
// storage for keys the caller never received a handle to, and a retried
// generation would consume more. Both destroys are attempted; cause is what the
// caller gets back, with the first cleanup failure attached.
func destroyKeyPair(session *pkcs11Session, pub, priv pkcs11.ObjectHandle, cause error) error {
	var cleanupErr error
	for _, h := range []pkcs11.ObjectHandle{priv, pub} {
		if err := session.ctx.DestroyObject(session.handle, h); err != nil && cleanupErr == nil {
			cleanupErr = err
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("%w (and destroying the generated key pair failed: %w)", cause, cleanupErr)
	}
	return cause
}
