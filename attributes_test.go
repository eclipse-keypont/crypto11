// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: MIT

package crypto11

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetNoPanicOnWrongType(t *testing.T) {
	a := NewAttributeSet()
	err := a.Set(CkaId, []string{"this is not allowed"})
	assert.Error(t, err)
}

func TestNewAttributeNoPanicOnWrongType(t *testing.T) {
	_, err := NewAttribute(CkaId, []string{"this is not allowed"})
	assert.Error(t, err)
}
