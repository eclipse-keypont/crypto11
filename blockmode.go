// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto/cipher"
	"errors"
	"runtime"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// cipher.BlockMode -----------------------------------------------------

// BlockModeCloser represents a block cipher running in a block-based mode (e.g. CBC).
//
// BlockModeCloser embeds cipher.BlockMode, and can be used as such.
// However, in this case
// (or if the Close() method is not explicitly called for any other reason),
// resources allocated to it may remain live indefinitely.
type BlockModeCloser interface {
	cipher.BlockMode

	// Close() releases resources associated with the block mode.
	Close()
}

const (
	modeEncrypt = iota // blockModeCloser is in encrypt mode
	modeDecrypt        // blockModeCloser is in decrypt mode
)

// NewCBCEncrypter returns a cipher.BlockMode which encrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size.
//
// The new BlockMode acquires persistent resources which are released (eventually) by a finalizer.
// If this is a problem for your application then use NewCBCEncrypterCloser instead.
//
// If that is not possible then adding calls to runtime.GC() may help.
func (key *SecretKey) NewCBCEncrypter(iv []byte) (cipher.BlockMode, error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeEncrypt, iv, true)
}

// NewCBCDecrypter returns a cipher.BlockMode which decrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size and must match the iv used to encrypt the data.
//
// The new BlockMode acquires persistent resources which are released (eventually) by a finalizer.
// If this is a problem for your application then use NewCBCDecrypterCloser instead.
//
// If that is not possible then adding calls to runtime.GC() may help.
func (key *SecretKey) NewCBCDecrypter(iv []byte) (cipher.BlockMode, error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeDecrypt, iv, true)
}

// NewCBCEncrypterCloser returns a  BlockModeCloser which encrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size.
//
// Use of NewCBCEncrypterCloser rather than NewCBCEncrypter represents a commitment to call the Close() method
// of the returned BlockModeCloser.
func (key *SecretKey) NewCBCEncrypterCloser(iv []byte) (BlockModeCloser, error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeEncrypt, iv, false)
}

// NewCBCDecrypterCloser returns a  BlockModeCloser which decrypts in cipher block chaining mode, using the given key.
// The length of iv must be the same as the key's block size and must match the iv used to encrypt the data.
//
// Use of NewCBCDecrypterCloser rather than NewCBCEncrypter represents a commitment to call the Close() method
// of the returned BlockModeCloser.
func (key *SecretKey) NewCBCDecrypterCloser(iv []byte) (BlockModeCloser, error) {
	return key.newBlockModeCloser(key.Cipher.CBCMech, modeDecrypt, iv, false)
}

// blockModeCloser is a concrete implementation of BlockModeCloser supporting CBC.
type blockModeCloser struct {
	// PKCS#11 session to use
	session *pkcs11Session

	// Cipher block size
	blockSize int

	// modeDecrypt or modeEncrypt
	mode int

	// Cleanup function. It takes the error the operation ended with, so that
	// a session the token declared dead is discarded rather than pooled.
	cleanup func(err error)
}

// newBlockModeCloser creates a new blockModeCloser for the chosen mechanism and mode.
func (key *SecretKey) newBlockModeCloser(mech uint, mode int, iv []byte, setFinalizer bool) (*blockModeCloser, error) {

	session, err := key.context.getSession()
	if err != nil {
		return nil, err
	}

	bmc := &blockModeCloser{
		session:   session,
		blockSize: key.Cipher.BlockSize,
		mode:      mode,
		cleanup: func(err error) {
			key.context.putSession(session, err)
		},
	}
	mechDescription := pkcs11.NewMechanism(mech, iv)

	switch mode {
	case modeDecrypt:
		err = session.ctx.DecryptInit(session.handle, mechDescription, key.handle)
	case modeEncrypt:
		err = session.ctx.EncryptInit(bmc.session.handle, mechDescription, key.handle)
	default:
		panic("unexpected mode")
	}
	if err != nil {
		bmc.cleanup(err)
		return nil, err
	}
	if setFinalizer {
		runtime.SetFinalizer(bmc, finalizeBlockModeCloser)
	}

	return bmc, nil
}

// finalizeBlockModeCloser is the runtime finalizer for block modes created
// without a Closer. It must never panic: a panic on the finalizer goroutine
// cannot be recovered by the application, so a token that fails C_*Final on an
// abandoned block mode would otherwise take the whole process down. The error
// has no one to go to and is dropped; the session is still released.
func finalizeBlockModeCloser(obj interface{}) {
	_ = obj.(*blockModeCloser).close()
}

func (bmc *blockModeCloser) BlockSize() int {
	return bmc.blockSize
}

func (bmc *blockModeCloser) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("destination buffer too small")
	}
	if len(src)%bmc.blockSize != 0 {
		panic("input is not a whole number of blocks")
	}
	var result []byte
	var err error
	switch bmc.mode {
	case modeDecrypt:
		result, err = bmc.session.ctx.DecryptUpdate(bmc.session.handle, src)
	case modeEncrypt:
		result, err = bmc.session.ctx.EncryptUpdate(bmc.session.handle, src)
	}
	if err != nil {
		// The operation is dead; nothing will reach Close for this block mode
		// in a way that helps. Release the session before panicking, or it —
		// and the Context's read lock — would be held until the finalizer
		// runs, if it ever does.
		bmc.session = nil
		bmc.cleanup(err)
		panic(err)
	}
	// The binding's buffer is a second copy of the output — plaintext, in
	// decrypt mode — that the caller cannot reach to clear. Wipe it once it
	// has been copied out, on the panic paths too.
	defer pkcs11.Wipe(result)
	// PKCS#11 2.40 s5.2 says that the operation must produce as much output
	// as possible, so we should never have less than we submitted for CBC.
	// This could be different for other modes but we don't implement any yet.
	if len(result) != len(src) {
		panic("nontrivial result from *Final operation")
	}
	copy(dst[:len(result)], result)
	runtime.KeepAlive(bmc)
}

// Close finalizes the operation and releases the session. A token error, or
// output where CBC can have none, is a panic: cipher.BlockMode has no way to
// return an error, and silently dropping either would hide a broken operation.
func (bmc *blockModeCloser) Close() {
	if err := bmc.close(); err != nil {
		panic(err)
	}
}

// close is the error-returning teardown shared by Close and the runtime
// finalizer. It is idempotent.
func (bmc *blockModeCloser) close() error {
	if bmc.session == nil {
		return nil
	}
	var result []byte
	var err error
	switch bmc.mode {
	case modeDecrypt:
		result, err = bmc.session.ctx.DecryptFinal(bmc.session.handle)
	case modeEncrypt:
		result, err = bmc.session.ctx.EncryptFinal(bmc.session.handle)
	}
	bmc.session = nil
	bmc.cleanup(err)
	if err != nil {
		return err
	}
	// PKCS#11 2.40 s5.2 says that the operation must produce as much output
	// as possible, so we should never have any left over for CBC.
	// This could be different for other modes but we don't implement any yet.
	if len(result) > 0 {
		pkcs11.Wipe(result)
		return errors.New("nontrivial result from *Final operation")
	}
	return nil
}
