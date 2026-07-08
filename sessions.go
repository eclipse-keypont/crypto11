// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"context"
	"errors"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/eclipse-keypont/crypto11/internal/pool"
)

// pkcs11Session wraps a PKCS#11 session handle so we can use it in a resource pool.
type pkcs11Session struct {
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

// Close is required to satisfy the pools.Resource interface. It closes the session, but swallows any
// errors that occur.
func (s pkcs11Session) Close() {
	// We cannot return an error, so we swallow it
	_ = s.ctx.CloseSession(s.handle)
}

// withSession executes a function with a session.
func (c *Context) withSession(f func(session *pkcs11Session) error) error {
	session, err := c.getSession()
	if err != nil {
		return err
	}
	defer c.pool.Put(session)

	return f(session)
}

// getSession retrieves a session from the pool, respecting the timeout defined in the Context config.
// Callers are responsible for putting this session back in the pool.
func (c *Context) getSession() (*pkcs11Session, error) {
	ctx := context.Background()

	if c.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.cfg.PoolWaitTimeout)
		defer cancel()
	}

	resource, err := c.pool.Get(ctx)
	if errors.Is(err, pool.ErrClosed) {
		// Our Context must have been closed, return a nicer error.
		// We don't use errClosed to ensure our tests identify functions that aren't checking for closure
		// correctly.
		return nil, errors.New("context is closed")
	}
	if err != nil {
		return nil, err
	}

	return resource.(*pkcs11Session), nil
}

// resourcePoolFactoryFunc is called by the resource pool when a new session is needed.
func (c *Context) resourcePoolFactoryFunc() (pool.Resource, error) {
	session, err := c.ctx.OpenSession(c.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &pkcs11Session{c.ctx.Ctx, session}, nil
}
