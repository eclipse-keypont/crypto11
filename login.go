// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// PKCS#11 login state belongs to the application, not to a session or a Context: once one
// Context has logged a token in, C_Login from another Context in the same process answers
// CKR_USER_ALREADY_LOGGED_IN without looking at the PIN, and PKCS#11 offers no way to check a PIN
// without side effects. So crypto11 remembers a keyed digest of the PIN it logged each token in
// with, and a later Context that presents a different PIN is refused rather than let in on the
// first one's login. The digest is an HMAC under a key drawn once per process, so it does not
// reveal the PIN on its own, and the records go when the module is finalized.

// errLoginPINMismatch is returned by Configure when the token is already logged in, by another
// Context in this process, with a different PIN or user type.
var errLoginPINMismatch = errors.New("crypto11: the token is already logged in by another Context with a different PIN")

var (
	// loginMu serialises a login with its record, so that a concurrent Configure cannot see the
	// token logged in before the record exists. It is taken before moduleReferencesMutex.
	loginMu sync.Mutex

	// loginRecords maps a module path and slot to the digest of the PIN crypto11 logged that
	// token in with. It is guarded by moduleReferencesMutex, which also guards its cleanup when
	// the module is finalized.
	loginRecords = map[loginKey][]byte{}

	loginDigestKey     []byte
	loginDigestKeyOnce sync.Once
)

type loginKey struct {
	path string
	slot pkcs11.SlotID
}

// pinDigest returns the keyed digest of a PIN for a user type.
func pinDigest(userType uint, pin []byte) []byte {
	loginDigestKeyOnce.Do(func() {
		loginDigestKey = make([]byte, 32)
		if _, err := rand.Read(loginDigestKey); err != nil {
			panic(fmt.Sprintf("crypto11: cannot draw the login digest key: %v", err))
		}
	})
	mac := hmac.New(sha256.New, loginDigestKey)
	_ = binary.Write(mac, binary.BigEndian, uint64(userType))
	_, _ = mac.Write(pin)
	return mac.Sum(nil)
}

// login logs the persistent session in with pin, which it wipes, and records or checks the
// login as described above. A token that was logged in outside crypto11 has no record, and its
// existing login is accepted as before.
func (c *Context) login(userType uint, pin []byte) error {
	digest := pinDigest(userType, pin)
	loginMu.Lock()
	defer loginMu.Unlock()
	err := c.ctx.Login(c.persistentSession, userType, pin)
	pkcs11.Wipe(pin)

	key := loginKey{path: c.ctx.path, slot: c.slot}
	moduleReferencesMutex.Lock()
	defer moduleReferencesMutex.Unlock()
	var pErr pkcs11.Error
	switch {
	case err == nil:
		loginRecords[key] = digest
		return nil
	case errors.As(err, &pErr) && pErr == pkcs11.CKR_USER_ALREADY_LOGGED_IN:
		if recorded, ok := loginRecords[key]; ok && !hmac.Equal(recorded, digest) {
			return errLoginPINMismatch
		}
		return nil
	default:
		return err
	}
}

// forgetLogins drops the login records of a module. The caller holds moduleReferencesMutex.
func forgetLogins(path string) {
	for key := range loginRecords {
		if key.path == path {
			delete(loginRecords, key)
		}
	}
}
