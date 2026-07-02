// SPDX-FileCopyrightText: 2017 Google Inc.
// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: Apache-2.0
//
// Vendored into crypto11 from github.com/thales-e-security/pool@v0.0.2, itself
// extracted from vitess.io/vitess; see internal/pool/README.md for provenance.
// Modified by Thales Group in 2026: reimplemented on top of Go's native typed
// atomics (sync/atomic.Int64 / atomic.Bool). This removes the 64-bit alignment
// footgun of the original hand-rolled version (which required atomic fields to be
// manually placed first in a struct to avoid runtime panics on 32-bit platforms)
// and drops the unused AtomicInt32 and AtomicString types.

package pool

import (
	"sync/atomic"
	"time"
)

// AtomicInt64 is a thin wrapper around atomic.Int64 exposing an
// Add/Set/Get/CompareAndSwap API. The zero value is ready to use and, unlike the
// original implementation, is safe to embed at any offset within a struct on all
// architectures. Like all sync/atomic types it must not be copied after first use.
type AtomicInt64 struct {
	v atomic.Int64
}

// Add atomically adds n to the value and returns the new value.
func (i *AtomicInt64) Add(n int64) int64 {
	return i.v.Add(n)
}

// Set atomically sets n as new value.
func (i *AtomicInt64) Set(n int64) {
	i.v.Store(n)
}

// Get atomically returns the current value.
func (i *AtomicInt64) Get() int64 {
	return i.v.Load()
}

// CompareAndSwap atomically swaps the old with the new value.
func (i *AtomicInt64) CompareAndSwap(oldval, newval int64) (swapped bool) {
	return i.v.CompareAndSwap(oldval, newval)
}

// AtomicDuration is an atomic time.Duration. The zero value is ready to use and
// must not be copied after first use.
type AtomicDuration struct {
	v atomic.Int64
}

// Add atomically adds duration to the value and returns the new value.
func (d *AtomicDuration) Add(duration time.Duration) time.Duration {
	return time.Duration(d.v.Add(int64(duration)))
}

// Set atomically sets duration as new value.
func (d *AtomicDuration) Set(duration time.Duration) {
	d.v.Store(int64(duration))
}

// Get atomically returns the current value.
func (d *AtomicDuration) Get() time.Duration {
	return time.Duration(d.v.Load())
}

// CompareAndSwap atomically swaps the old with the new value.
func (d *AtomicDuration) CompareAndSwap(oldval, newval time.Duration) (swapped bool) {
	return d.v.CompareAndSwap(int64(oldval), int64(newval))
}

// AtomicBool is an atomic boolean. The zero value is false, is ready to use and
// must not be copied after first use.
type AtomicBool struct {
	v atomic.Bool
}

// Set atomically sets n as new value.
func (i *AtomicBool) Set(n bool) {
	i.v.Store(n)
}

// Get atomically returns the current value.
func (i *AtomicBool) Get() bool {
	return i.v.Load()
}

// CompareAndSwap atomically swaps the old with the new value.
func (i *AtomicBool) CompareAndSwap(o, n bool) (swapped bool) {
	return i.v.CompareAndSwap(o, n)
}
