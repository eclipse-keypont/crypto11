// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
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
func (c *Context) withSession(f func(session *pkcs11Session) error) (err error) {
	session, err := c.getSession()
	if err != nil {
		return err
	}
	defer func() { c.putSession(session, err) }()

	return f(session)
}

// putSession returns a session to the pool once an operation on it has finished
// with err, and releases the read lock getSession took. A session the token has
// declared dead is closed and replaced instead of being handed to the next
// caller: returning it would make every operation that happens to draw it fail
// the same way, long after the fault that killed it.
func (c *Context) putSession(session *pkcs11Session, err error) {
	defer c.ops.RUnlock()
	if sessionFatal(err) {
		session.Close()
		// A nil resource tells the pool to open a fresh session in its place.
		c.pool.Put(nil)
		return
	}
	c.pool.Put(session)
}

// sessionFatal reports whether err says the session it came from — or the token
// behind it — can no longer be used. The list is deliberately narrow: an error
// about the request (a bad mechanism, a wrong key, an invalid PIN) leaves the
// session perfectly usable, and recycling on those would just cost a C_OpenSession
// per failed call.
func sessionFatal(err error) bool {
	var p11Err pkcs11.Error
	if !errors.As(err, &p11Err) {
		return false
	}
	switch p11Err {
	case pkcs11.CKR_SESSION_HANDLE_INVALID,
		pkcs11.CKR_SESSION_CLOSED,
		pkcs11.CKR_DEVICE_ERROR,
		pkcs11.CKR_DEVICE_REMOVED,
		pkcs11.CKR_TOKEN_NOT_PRESENT,
		pkcs11.CKR_GENERAL_ERROR,
		// A stuck multi-part operation: C_*Init keeps failing on this session
		// until it is closed, and nothing we can call from here unsticks it.
		pkcs11.CKR_OPERATION_ACTIVE:
		return true
	}
	return false
}

// getSession retrieves a session from the pool, respecting the timeout defined in the Context config.
// Callers are responsible for handing this session back through putSession.
//
// The session comes with the Context's read lock held: from here until putSession, Close cannot
// run. That is what makes "is the Context still open?" and "take a session" one step rather than
// two — a check-then-act that Close could otherwise slip between.
func (c *Context) getSession() (*pkcs11Session, error) {
	c.ops.RLock()
	if c.closed.Get() {
		c.ops.RUnlock()
		// We don't use errClosed to ensure our tests identify functions that aren't checking for closure
		// correctly.
		return nil, errors.New("context is closed")
	}

	ctx := context.Background()

	if c.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.cfg.PoolWaitTimeout)
		defer cancel()
	}

	resource, err := c.pool.Get(ctx)
	if errors.Is(err, pool.ErrClosed) {
		// Our Context must have been closed, return a nicer error.
		c.ops.RUnlock()
		return nil, errors.New("context is closed")
	}
	if err != nil {
		c.ops.RUnlock()
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
