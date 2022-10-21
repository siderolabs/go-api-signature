// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package client

import (
	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

// Key represents an OpenPGP client key pair associated with a context and an identity.
// It is stored on the filesystem.
type Key struct {
	*pgp.Key
	context  string
	identity string
}
