// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"context"
	"errors"
	"fmt"
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
	defer c.endOp()
	if sessionFatal(err) {
		session.Close()
		// A nil resource tells the pool to open a fresh session in its place.
		c.pool.Put(nil)
		return
	}
	c.pool.Put(session)
}

// errOperationAbandoned marks the error of a token operation, run after its C_*Init, that did not
// come from the token: the binding gave up on the call, for instance on an output over its size
// limit, and the token was never told, so the operation may still be active on the session.
// sessionFatal retires such a session, which would otherwise make the next caller's C_*Init fail
// with CKR_OPERATION_ACTIVE.
var errOperationAbandoned = errors.New("crypto11: token operation abandoned")

// operationError returns err, the error of a token operation run after its C_*Init, marked with
// errOperationAbandoned unless it is a bare pkcs11.Error: the token's own return value, after
// which PKCS#11 says the operation has ended.
func operationError(err error) error {
	if err == nil {
		return nil
	}
	if _, fromToken := err.(pkcs11.Error); fromToken { //nolint:errorlint // only the bare value says the token answered
		return err
	}
	return fmt.Errorf("%w: %w", errOperationAbandoned, err)
}

// opResult is operationError for a call that returns a value as well.
func opResult[T any](v T, err error) (T, error) {
	return v, operationError(err)
}

// sessionFatal reports whether err says the session it came from — or the token
// behind it — can no longer be used. The list is deliberately narrow: an error
// about the request (a bad mechanism, a wrong key, an invalid PIN) leaves the
// session perfectly usable, and recycling on those would just cost a C_OpenSession
// per failed call.
func sessionFatal(err error) bool {
	if errors.Is(err, errOperationAbandoned) {
		return true
	}
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
		// The login went away underneath the Context. Replacing the session runs
		// checkNewSession, which reports it as errLoginLost.
		pkcs11.CKR_USER_NOT_LOGGED_IN,
		// A stuck multi-part operation: C_*Init keeps failing on this session
		// until it is closed, and nothing we can call from here unsticks it.
		pkcs11.CKR_OPERATION_ACTIVE:
		return true
	}
	return false
}

// isSessionObject reports whether attrs makes a session object: CKA_TOKEN set to false.
func isSessionObject(attrs AttributeSet) bool {
	a, ok := attrs[pkcs11.CKA_TOKEN]
	return ok && a != nil && len(a.Value) > 0 && a.Value[0] == 0
}

// withObjectSession runs f, which creates objects from templates and returns them to the caller.
//
// A session object (CKA_TOKEN = false) lives only as long as the session that created it, and a
// pooled session can be closed at any time: retired after an error, perhaps on another caller's
// operation. So when any template makes a session object, f runs on the Context's persistent
// session, which lasts as long as the Context, one caller at a time; otherwise on a pooled
// session, as withSession.
func (c *Context) withObjectSession(templates []AttributeSet, f func(session *pkcs11Session) error) error {
	for _, t := range templates {
		if isSessionObject(t) {
			return c.withPersistentSession(f)
		}
	}
	return c.withSession(f)
}

// withPersistentSession runs f on the Context's persistent session, counted as an operation in
// flight, as getSession does, and under persistentMu, since a session must not be used
// concurrently.
func (c *Context) withPersistentSession(f func(session *pkcs11Session) error) error {
	if err := c.beginOp(); err != nil {
		return err
	}
	defer c.endOp()
	c.persistentMu.Lock()
	defer c.persistentMu.Unlock()
	return f(&pkcs11Session{c.ctx.Ctx, c.persistentSession})
}

// errContextClosing is returned to an operation that starts, or waits for a pooled session, once
// Close has begun. We don't use errClosed to ensure our tests identify functions that aren't
// checking for closure correctly.
var errContextClosing = errors.New("context is closed")

// beginOp counts an operation in flight, so that Close waits for it, unless Close has begun, in
// which case it fails at once rather than waiting behind Close.
func (c *Context) beginOp() error {
	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	if c.closing || c.closed.Get() {
		return errContextClosing
	}
	c.activeOps.Add(1)
	return nil
}

// endOp ends an operation counted by beginOp.
func (c *Context) endOp() {
	c.activeOps.Done()
}

// getSession retrieves a session from the pool, respecting the timeout defined in the Context config.
// Callers are responsible for handing this session back through putSession.
//
// The session comes counted as an operation in flight (beginOp): from here until putSession,
// Close waits. That is what makes "is the Context still open?" and "take a session" one step
// rather than two — a check-then-act that Close could otherwise slip between. Once Close has
// begun, getSession fails at once, and a wait for a pooled session is cut short.
func (c *Context) getSession() (*pkcs11Session, error) {
	if err := c.beginOp(); err != nil {
		return nil, err
	}

	ctx := c.closeCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if c.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.PoolWaitTimeout)
		defer cancel()
	}

	resource, err := c.pool.Get(ctx)
	if err != nil {
		c.endOp()
		if errors.Is(err, pool.ErrClosed) || (c.closeCtx != nil && c.closeCtx.Err() != nil) {
			// Our Context is closing, return a nicer error.
			return nil, errContextClosing
		}
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

	// IdleReused is the cumulative number of times an operation was served by a
	// session that was already open rather than by opening a new one. It only
	// ever grows. A high value against a low Active count is the pool doing its
	// job: reusing idle sessions instead of opening one per request.
	IdleReused int64
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
		IdleReused:  c.pool.IdleReused(),
	}
}

// sessionFlags returns the flags every session crypto11 opens is created with.
//
// CKF_SERIAL_SESSION is mandatory in PKCS#11 v2.0 and later, so it is always
// set. CKF_RW_SESSION is added unless Config.ReadOnlySessions asks for
// read-only sessions, which is what tokens that reject a read/write session
// (CKR_TOKEN_WRITE_PROTECTED) require.
func (c *Context) sessionFlags() uint {
	flags := uint(pkcs11.CKF_SERIAL_SESSION)
	if !c.cfg.ReadOnlySessions {
		flags |= pkcs11.CKF_RW_SESSION
	}
	return flags
}

// errLoginLost is returned when a session the pool opens is not logged in, although the Context
// logged in when it was configured: the login went away underneath it, through a C_Logout
// elsewhere in the process, a login timeout on the HSM, or a reconnect. crypto11 does not keep the
// PIN, so it cannot log in again; close the Context and configure a new one.
var errLoginLost = errors.New("crypto11: the token is no longer logged in; close the Context and configure a new one")

// errTokenChanged is returned when the slot no longer holds the token the Context was configured
// for, as after a token was removed and another inserted.
var errTokenChanged = errors.New("crypto11: the slot no longer holds the token the Context was configured for")

// resourcePoolFactoryFunc is called by the resource pool when a new session is needed. The new
// session is checked (checkNewSession) before the pool hands it out.
func (c *Context) resourcePoolFactoryFunc() (pool.Resource, error) {
	session, err := c.ctx.OpenSession(c.slot, c.sessionFlags())
	if err != nil {
		return nil, err
	}
	if err := c.checkNewSession(session); err != nil {
		_ = c.ctx.CloseSession(session)
		return nil, err
	}
	return &pkcs11Session{c.ctx.Ctx, session}, nil
}

// checkNewSession checks a session the pool has just opened: the slot must still hold the token
// the Context was configured for, and, unless the Context does not log in, the session must be
// logged in. Login state is shared by every session of the application, so a new session that is
// not logged in means the login is gone, and the finders would otherwise go on searching only the
// token's public objects. The pool keeps its sessions, so this runs when one is replaced, after a
// session error such as CKR_USER_NOT_LOGGED_IN or CKR_DEVICE_REMOVED, not on every operation.
func (c *Context) checkNewSession(session pkcs11.SessionHandle) error {
	token, err := c.ctx.GetTokenInfo(c.slot)
	if err != nil {
		return err
	}
	if token.SerialNumber != c.token.SerialNumber || token.Label != c.token.Label {
		return errTokenChanged
	}
	if c.cfg.LoginNotSupported {
		return nil
	}
	info, err := c.ctx.GetSessionInfo(session)
	if err != nil {
		return err
	}
	if info.State == pkcs11.CKS_RO_PUBLIC_SESSION || info.State == pkcs11.CKS_RW_PUBLIC_SESSION {
		return errLoginLost
	}
	return nil
}
