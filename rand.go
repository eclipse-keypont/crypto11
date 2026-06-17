// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"io"
)

// NewRandomReader returns a reader for the random number generator on the token.
func (c *Context) NewRandomReader() (io.Reader, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	return pkcs11RandReader{c}, nil
}

// pkcs11RandReader is a random number reader that uses PKCS#11.
type pkcs11RandReader struct {
	context *Context
}

// This implements the Reader interface for pkcs11RandReader.
func (r pkcs11RandReader) Read(data []byte) (n int, err error) {
	var result []byte

	if err = r.context.withSession(func(session *pkcs11Session) error {
		result, err = r.context.ctx.GenerateRandom(session.handle, len(data))
		return err
	}); err != nil {
		return 0, err
	}
	copy(data, result)
	return len(result), err
}
