// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: MIT

package crypto11

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var threadCount = 32
var signaturesPerThread = 256

func TestThreadedRSA(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ctx, err := ConfigureFromFile("crypto11.config.json")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, ctx.Close())
	}()

	id := randomBytes()
	key, err := ctx.GenerateRSAKeyPair(id, rsaSize)
	require.NoError(t, err)
	defer func(k Signer) { _ = k.Delete() }(key)

	done := make(chan int)
	started := time.Now()

	t.Logf("Starting %v threads", threadCount)

	for i := 0; i < threadCount; i++ {
		go signingRoutine(t, key, done)

		// CloudHSM falls over if you create sessions too quickly
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("Waiting for %v threads", threadCount)
	for i := 0; i < threadCount; i++ {
		<-done
	}
	finished := time.Now()
	ticks := finished.Sub(started)
	elapsed := float64(ticks) / 1000000000.0
	t.Logf("Made %v signatures in %v elapsed (%v/s)",
		threadCount*signaturesPerThread,
		elapsed, float64(threadCount*signaturesPerThread)/elapsed)
}

func signingRoutine(t *testing.T, key crypto.Signer, done chan int) {
	for i := 0; i < signaturesPerThread; i++ {
		testRsaSigningPKCS1v15(t, key, crypto.SHA1)

		// CloudHSM falls over if you create sessions too quickly
		time.Sleep(50 * time.Millisecond)
	}
	done <- 1
}
