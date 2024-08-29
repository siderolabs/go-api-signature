// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build race

package pgp_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

func TestKeyFlowParallel(t *testing.T) {
	key, err := pgp.GenerateKey("John Smith", "Linux", "john.smith@example.com", time.Hour)
	require.NoError(t, err)

	t.Run("parallel_section", func(t *testing.T) {
		for range 10 {
			t.Run("KeyFlow", func(t *testing.T) {
				t.Parallel()

				for range 10 {
					testKeyFlow(t, key)
				}
			})
		}
	})
}
