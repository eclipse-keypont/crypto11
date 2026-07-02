// SPDX-FileCopyrightText: 2017 Google Inc.
// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: Apache-2.0
//
// Vendored into crypto11 from github.com/thales-e-security/pool@v0.0.2, itself
// extracted from vitess.io/vitess; see internal/pool/README.md for provenance.

package pool

import (
	"sync/atomic"
	"testing"
	"time"
)

const (
	half    = time.Duration(500e5)
	quarter = time.Duration(250e5)
	tenth   = time.Duration(100e5)
)

var numcalls int32

func f() {
	atomic.AddInt32(&numcalls, 1)
}

func TestWait(t *testing.T) {
	atomic.StoreInt32(&numcalls, 0)
	timer := NewTimer(quarter)
	timer.Start(f)
	defer timer.Stop()
	time.Sleep(tenth)
	if atomic.LoadInt32(&numcalls) != 0 {
		t.Errorf("want 0, received %v", numcalls)
	}
	time.Sleep(quarter)
	if atomic.LoadInt32(&numcalls) != 1 {
		t.Errorf("want 1, received %v", numcalls)
	}
	time.Sleep(quarter)
	if atomic.LoadInt32(&numcalls) != 2 {
		t.Errorf("want 1, received %v", numcalls)
	}
}

func TestReset(t *testing.T) {
	atomic.StoreInt32(&numcalls, 0)
	timer := NewTimer(half)
	timer.Start(f)
	defer timer.Stop()
	timer.SetInterval(quarter)
	time.Sleep(tenth)
	if atomic.LoadInt32(&numcalls) != 0 {
		t.Errorf("want 0, received %v", numcalls)
	}
	time.Sleep(quarter)
	if atomic.LoadInt32(&numcalls) != 1 {
		t.Errorf("want 1, received %v", numcalls)
	}
}

func TestIndefinite(t *testing.T) {
	atomic.StoreInt32(&numcalls, 0)
	timer := NewTimer(0)
	timer.Start(f)
	defer timer.Stop()
	timer.TriggerAfter(quarter)
	time.Sleep(tenth)
	if atomic.LoadInt32(&numcalls) != 0 {
		t.Errorf("want 0, received %v", numcalls)
	}
	time.Sleep(quarter)
	if atomic.LoadInt32(&numcalls) != 1 {
		t.Errorf("want 1, received %v", numcalls)
	}
}
