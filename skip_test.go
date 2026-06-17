// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-License-Identifier: MIT

package crypto11

import (
	"os"
	"strings"
	"testing"
)

const skipTestEnv = "CRYPTO11_SKIP"
const skipTestCert = "CERTS"
const skipTestOAEPLabel = "OAEP_LABEL"
const skipTestDSA = "DSA"

// skipTest tests whether the CRYPTO11_SKIP environment variable contains
// flagName. If so, it skips the test.
func skipTest(t *testing.T, flagName string) {
	if shouldSkipTest(flagName) {
		t.Logf("Skipping test due to %s flag", flagName)
		t.SkipNow()
	}
}

func shouldSkipTest(flagName string) bool {
	thingsToSkip := strings.Split(os.Getenv(skipTestEnv), ",")
	for _, s := range thingsToSkip {
		if s == flagName {
			return true
		}
	}
	return false
}
