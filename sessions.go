// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"context"
	"errors"
	"time"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"

	"github.com/eclipse-keypont/crypto11/v2/internal/pool"
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

// PoolStats is a snapshot of a Context's session pool counters, as returned by
// Context.PoolStats. It is a plain value with no reference to the pool itself,
// so it is safe to keep, copy and marshal (durations marshal to JSON as
// nanoseconds).
//
// The fields are read one at a time from the pool's atomic counters rather than
// under a lock, so a snapshot taken while other goroutines are using the token
// is individually accurate but not necessarily internally consistent: Available
// and InUse need not add up to Capacity.
type PoolStats struct {
	// Capacity is the number of sessions the pool may hand out. crypto11 keeps
	// one session of its own to hold the login state, so this is one less than
	// the effective MaxSessions. Closing the Context sets it to zero.
	Capacity int64

	// Available is the number of sessions that could be taken from the pool
	// without waiting. A session that has not been opened yet still counts as
	// available: the pool opens it on first use.
	Available int64

	// Active is the number of sessions actually open on the token, whether idle
	// in the pool or currently claimed. It grows towards Capacity as load
	// requires, and never shrinks unless sessions are closed.
	Active int64

	// InUse is the number of sessions claimed by in-flight operations.
	InUse int64

	// MaxCapacity is the ceiling Capacity could be raised to. crypto11 creates
	// the pool at full size, so this is the initial Capacity and, unlike
	// Capacity, it is unaffected by Close.
	MaxCapacity int64

	// WaitCount is the cumulative number of operations that had to wait for a
	// session because none was available, and WaitTime the total time they
	// spent waiting. Both only ever grow. A rising WaitCount means MaxSessions
	// is below what the workload needs (or that Config.PoolWaitTimeout is about
	// to start biting).
	WaitCount int64
	WaitTime  time.Duration

	// IdleTimeout is how long an idle session is kept before being closed and
	// replaced, and IdleClosed the number of sessions closed that way. crypto11
	// does not currently enable idle timeouts, so both are always zero; they
	// are reported for completeness.
	IdleTimeout time.Duration
	IdleClosed  int64
}

// PoolStats returns a snapshot of the state of the session pool, for metrics
// and diagnostics.
//
// It only reads counters the pool maintains in memory: no PKCS#11 call is made
// and no session is taken, so it is cheap and safe to call from a metrics
// scrape, concurrently with any other operation, and on a closed Context (where
// it reports the pool as it was torn down, with Capacity zero).
func (c *Context) PoolStats() PoolStats {
	if c.pool == nil {
		// Only reachable for a Context that did not come from Configure.
		return PoolStats{}
	}

	return PoolStats{
		Capacity:    c.pool.Capacity(),
		Available:   c.pool.Available(),
		Active:      c.pool.Active(),
		InUse:       c.pool.InUse(),
		MaxCapacity: c.pool.MaxCap(),
		WaitCount:   c.pool.WaitCount(),
		WaitTime:    c.pool.WaitTime(),
		IdleTimeout: c.pool.IdleTimeout(),
		IdleClosed:  c.pool.IdleClosed(),
	}
}

// resourcePoolFactoryFunc is called by the resource pool when a new session is needed.
func (c *Context) resourcePoolFactoryFunc() (pool.Resource, error) {
	session, err := c.ctx.OpenSession(c.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &pkcs11Session{c.ctx.Ctx, session}, nil
}
