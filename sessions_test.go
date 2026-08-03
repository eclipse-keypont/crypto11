// SPDX-FileCopyrightText: 2026 Thales Group and the crypto11 Contributors
// SPDX-License-Identifier: MIT

package crypto11

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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
	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	before := ctx.PoolStats()
	require.Positive(t, before.Capacity, "the pool should be able to hand out sessions")
	assert.Equal(t, before.Capacity, before.MaxCapacity, "the pool is created at full size")
	assert.Equal(t, before.Capacity, before.Available)
	assert.Equal(t, int64(0), before.InUse)

	err = ctx.withSession(func(_ *pkcs11Session) error {
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
