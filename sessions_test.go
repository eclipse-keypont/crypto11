// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	pkcs11 "github.com/eclipse-keypont/pkcs11-go/cryptoki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-keypont/crypto11/v2/internal/pool"
)

// fakeSession stands in for a pkcs11Session so the pool can be exercised
// without a token.
type fakeSession struct{}

func (fakeSession) Close() {}

// TestPoolStatsFields drives every PoolStats field from a pool of fake
// resources, so the mapping is checked without needing a token.
func TestPoolStatsFields(t *testing.T) {
	p := pool.NewResourcePool(
		func() (pool.Resource, error) { return fakeSession{}, nil },
		2, 4, time.Hour, 0)
	defer p.Close()

	c := &Context{pool: p}

	assert.Equal(t, PoolStats{
		Capacity:    2,
		Available:   2,
		MaxCapacity: 4,
		IdleTimeout: time.Hour,
	}, c.PoolStats(), "a pool nobody has used yet has no sessions open")

	ctx := context.Background()
	first, err := p.Get(ctx)
	require.NoError(t, err)
	second, err := p.Get(ctx)
	require.NoError(t, err)

	stats := c.PoolStats()
	assert.Equal(t, int64(0), stats.Available)
	assert.Equal(t, int64(2), stats.Active, "both sessions have now been opened")
	assert.Equal(t, int64(2), stats.InUse)
	assert.Equal(t, int64(0), stats.WaitCount)

	// With both resources claimed, a third Get has to wait for one back.
	type getResult struct {
		resource pool.Resource
		err      error
	}
	got := make(chan getResult)
	go func() {
		r, getErr := p.Get(ctx)
		got <- getResult{r, getErr}
	}()

	time.Sleep(50 * time.Millisecond)
	p.Put(first)
	third := <-got
	require.NoError(t, third.err)

	stats = c.PoolStats()
	assert.Equal(t, int64(1), stats.WaitCount)
	assert.Positive(t, stats.WaitTime)
	assert.Equal(t, int64(2), stats.Active, "waiting for a session does not open another")
	assert.Equal(t, int64(2), stats.InUse)

	p.Put(second)
	p.Put(third.resource)

	stats = c.PoolStats()
	assert.Equal(t, int64(2), stats.Available)
	assert.Equal(t, int64(0), stats.InUse)
	assert.Equal(t, int64(0), stats.IdleClosed, "nothing has been idle for an hour")
}

// TestPoolStatsNoPool checks a Context that never went through Configure
// reports zeroes instead of panicking.
func TestPoolStatsNoPool(t *testing.T) {
	assert.Equal(t, PoolStats{}, (&Context{}).PoolStats())
}

// TestPoolStatsMarshalsToJSON covers the metrics-scrape use case the API exists
// for: durations are nanoseconds, as they were in the pool's own JSON.
func TestPoolStatsMarshalsToJSON(t *testing.T) {
	encoded, err := json.Marshal(PoolStats{
		Capacity:    3,
		Available:   1,
		Active:      2,
		InUse:       2,
		MaxCapacity: 3,
		WaitCount:   1,
		WaitTime:    250 * time.Millisecond,
	})
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"Capacity": 3, "Available": 1, "Active": 2, "InUse": 2, "MaxCapacity": 3,
		"WaitCount": 1, "WaitTime": 250000000, "IdleTimeout": 0, "IdleClosed": 0
	}`, string(encoded))
}

// TestContextPoolStats checks the counters against a real token, including
// while a session is checked out and after the Context is closed.
func TestContextPoolStats(t *testing.T) {
	ctx := testContext(t)

	before := ctx.PoolStats()
	require.Positive(t, before.Capacity, "the pool should be able to hand out sessions")
	assert.Equal(t, before.Capacity, before.MaxCapacity, "the pool is created at full size")
	assert.Equal(t, before.Capacity, before.Available)
	assert.Equal(t, int64(0), before.InUse)

	err := ctx.withSession(func(_ *pkcs11Session) error {
		stats := ctx.PoolStats()
		assert.Equal(t, int64(1), stats.InUse, "we are holding a session")
		assert.Equal(t, before.Available-1, stats.Available)
		assert.GreaterOrEqual(t, stats.Active, int64(1), "our session is open on the token")
		return nil
	})
	require.NoError(t, err)

	after := ctx.PoolStats()
	assert.Equal(t, int64(0), after.InUse, "the session went back to the pool")
	assert.Equal(t, before.Available, after.Available)

	require.NoError(t, ctx.Close())

	closed := ctx.PoolStats()
	assert.Equal(t, int64(0), closed.Capacity, "Close drains the pool")
	assert.Equal(t, before.MaxCapacity, closed.MaxCapacity, "but does not forget how big it was")
}

func TestSessionFatal(t *testing.T) {
	fatal := []uint{
		pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_SESSION_CLOSED, pkcs11.CKR_DEVICE_ERROR,
		pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_GENERAL_ERROR,
		pkcs11.CKR_OPERATION_ACTIVE,
	}
	for _, code := range fatal {
		assert.True(t, sessionFatal(pkcs11.Error(code)), "%v must discard the session", pkcs11.Error(code))
		// Wrapped errors are unwrapped.
		assert.True(t, sessionFatal(fmt.Errorf("op: %w", pkcs11.Error(code))))
	}

	benign := []uint{
		pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_MECHANISM_INVALID, pkcs11.CKR_KEY_HANDLE_INVALID,
		pkcs11.CKR_USER_NOT_LOGGED_IN, pkcs11.CKR_TEMPLATE_INCONSISTENT, pkcs11.CKR_OBJECT_HANDLE_INVALID,
	}
	for _, code := range benign {
		assert.False(t, sessionFatal(pkcs11.Error(code)), "%v must keep the session", pkcs11.Error(code))
	}
	assert.False(t, sessionFatal(nil))
	assert.False(t, sessionFatal(errors.New("not a pkcs11 error")))
}

func TestPoisonedSessionIsReplaced(t *testing.T) {
	// MaxSessions=2 leaves exactly one pooled session, so an operation after the
	// poisoning has no other session to draw: it either recovers or it does not.
	cfg := testConfig(t)
	cfg.MaxSessions = 2
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	defer ctx.Close()

	// Kill the pooled session behind the pool's back, then hand it back as if
	// nothing had happened — the state a CKR_DEVICE_ERROR or a token reset leaves
	// behind.
	s, err := ctx.getSession()
	require.NoError(t, err)
	require.NoError(t, s.ctx.CloseSession(s.handle))
	ctx.pool.Put(s)

	_, err = ctx.FindKeys(randomBytes(), nil)
	require.Error(t, err, "the dead session must surface an error once")
	var p11Err pkcs11.Error
	require.True(t, errors.As(err, &p11Err))
	assert.Equal(t, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID), p11Err)

	// The pool must have replaced it: without putSession this call would fail
	// with CKR_SESSION_HANDLE_INVALID forever.
	_, err = ctx.FindKeys(randomBytes(), nil)
	require.NoError(t, err, "a fresh session must have replaced the dead one")
}
