// Copyright 2024 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
