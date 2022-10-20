// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package jwt

import "context"

// Claims represents the claims of a JWT.
type Claims struct {
	VerifiedEmail string `json:"email"`
}

// Verifier is able to verify a JWT and extract its claims.
type Verifier interface {
	Verify(ctx context.Context, token string) (*Claims, error)
}
