// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pgp_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

func TestKeyFlow(t *testing.T) {
	key, err := pgp.GenerateKey("John Smith", "Linux", "john.smith@example.com", time.Hour)
	require.NoError(t, err)

	assert.True(t, key.IsPrivate())
	assert.NoError(t, key.Validate())

	message := []byte("Hello, World!")

	signature, err := key.Sign(message)
	require.NoError(t, err)

	assert.NoError(t, key.Verify(message, signature))
	assert.Error(t, key.Verify(message[:len(message)-1], signature))
	assert.Error(t, key.Verify(message, signature[:len(signature)-1]))
}
