// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build unix

package fileutils

import "golang.org/x/sys/unix"

// IsWritable checks if the specified path is writable.
func IsWritable(path string) bool {
	err := unix.Access(path, unix.W_OK)

	return err == nil
}
