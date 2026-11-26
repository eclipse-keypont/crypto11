// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

//go:build !unix

package crypto11

import "os"

// checkConfigFileOwner is not implemented where file ownership is not a Unix user ID.
func checkConfigFileOwner(os.FileInfo) error {
	return nil
}
