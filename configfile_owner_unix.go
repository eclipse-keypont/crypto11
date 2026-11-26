// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: MIT

//go:build unix

package crypto11

import (
	"fmt"
	"os"
	"syscall"
)

// checkConfigFileOwner refuses a config file owned by anyone but the current user or root.
// Whoever owns the file can change its mode and rewrite it, so the mode checks say nothing
// about a file someone else owns, and the file names the library Configure loads.
func checkConfigFileOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := int(st.Uid); uid != os.Geteuid() && uid != 0 {
		return fmt.Errorf("owned by uid %d, which is neither this process's user (%d) nor root", uid, os.Geteuid())
	}
	return nil
}
