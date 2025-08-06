// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package fileutils

import "os"

// FileExists checks if specified file exists.
func FileExists(filename string) bool {
	if _, err := os.Stat(filename); err != nil {
		return false
	}

	return true
}
