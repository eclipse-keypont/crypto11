// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// closingContext configures a Context with maxSessions, gives it a CBC encrypter, which holds a
// pooled session until it is closed, and starts Close, which waits for that session. It returns
// the Context, the encrypter, and a channel closed when Close returns.
func closingContext(t *testing.T, maxSessions int) (*Context, interface{ Close() }, chan struct{}) {
	t.Helper()
	cfg := testConfig(t)
	cfg.MaxSessions = maxSessions
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	id := randomBytes()
	key, err := ctx.GenerateSecretKey(id, 256, CipherAES)
	require.NoError(t, err)
	t.Cleanup(func() {
		// The Context is closed by then: delete the key through a fresh one.
		other, err := Configure(testConfig(t))
		require.NoError(t, err)
		if k, err := other.FindKey(id, nil); err == nil {
			_ = k.Delete()
		}
		_ = other.Close()
	})
	bm, err := key.NewCBCEncrypterCloser(make([]byte, 16))
	require.NoError(t, err)

	closed := make(chan struct{})
	go func() { _ = ctx.Close(); close(closed) }()
	require.Eventually(t, func() bool {
		ctx.opsMu.Lock()
		defer ctx.opsMu.Unlock()
		return ctx.closing
	}, 2*time.Second, 10*time.Millisecond, "Close did not start")
	return ctx, bm, closed
}

// requireWithin fails unless done is closed within d.
func requireWithin(t *testing.T, done <-chan struct{}, d time.Duration, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal(msg)
	}
}

// TestOperationDuringCloseFailsInsteadOfBlocking checks that an operation started while Close
// waits for a session, by the goroutine holding that session for instance, fails at once rather
// than waiting behind Close, which waits for it: a deadlock.
func TestOperationDuringCloseFailsInsteadOfBlocking(t *testing.T) {
	ctx, bm, closed := closingContext(t, 8)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ctx.FindKeys(randomBytes(), nil)
		require.Error(t, err)
	}()
	requireWithin(t, done, 3*time.Second, "an operation started during Close blocked")

	bm.Close()
	requireWithin(t, closed, 3*time.Second, "Close did not return once the session was given back")
}

// TestCloseWakesPoolWaiter checks that Close wakes an operation waiting, with no timeout, for a
// pooled session, which would otherwise wait for ever, and Close with it, if its caller held the
// session it waits for.
func TestCloseWakesPoolWaiter(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSessions = 2 // a single pooled session
	ctx, err := Configure(cfg)
	require.NoError(t, err)
	held, err := ctx.getSession()
	require.NoError(t, err)

	waited := make(chan struct{})
	go func() {
		defer close(waited)
		_, err := ctx.FindKeys(randomBytes(), nil)
		require.ErrorIs(t, err, errContextClosing)
	}()
	time.Sleep(200 * time.Millisecond) // the operation is now waiting for the held session

	closed := make(chan struct{})
	go func() { _ = ctx.Close(); close(closed) }()
	requireWithin(t, waited, 3*time.Second, "Close did not wake the operation waiting for a session")

	ctx.putSession(held, nil)
	requireWithin(t, closed, 3*time.Second, "Close did not return once the session was given back")
}
