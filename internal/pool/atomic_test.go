// SPDX-FileCopyrightText: 2017 Google Inc.
// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: Apache-2.0
//
// Vendored into crypto11 from github.com/thales-e-security/pool@v0.0.2, itself
// extracted from vitess.io/vitess; see internal/pool/README.md for provenance.

package pool

import (
	"testing"
)

func TestAtomicString(t *testing.T) {
	var s AtomicString
	if s.Get() != "" {
		t.Errorf("want empty, got %s", s.Get())
	}
	s.Set("a")
	if s.Get() != "a" {
		t.Errorf("want a, got %s", s.Get())
	}
	if s.CompareAndSwap("b", "c") {
		t.Errorf("want false, got true")
	}
	if s.Get() != "a" {
		t.Errorf("want a, got %s", s.Get())
	}
	if !s.CompareAndSwap("a", "c") {
		t.Errorf("want true, got false")
	}
	if s.Get() != "c" {
		t.Errorf("want c, got %s", s.Get())
	}
}

func TestAtomicBool(t *testing.T) {
	b := NewAtomicBool(true)
	if !b.Get() {
		t.Error("b.Get: false, want true")
	}
	b.Set(false)
	if b.Get() {
		t.Error("b.Get: true, want false")
	}
	b.Set(true)
	if !b.Get() {
		t.Error("b.Get: false, want true")
	}

	if b.CompareAndSwap(false, true) {
		t.Error("b.CompareAndSwap false, true should fail")
	}
	if !b.CompareAndSwap(true, false) {
		t.Error("b.CompareAndSwap true, false should succeed")
	}
	if !b.CompareAndSwap(false, false) {
		t.Error("b.CompareAndSwap false, false should NOP")
	}
	if !b.CompareAndSwap(false, true) {
		t.Error("b.CompareAndSwap false, true should succeed")
	}
	if !b.CompareAndSwap(true, true) {
		t.Error("b.CompareAndSwap true, true should NOP")
	}
}
