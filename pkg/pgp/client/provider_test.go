// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package client_test

import (
	"testing"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/pgp/client"
)

func TestKeyProvider(t *testing.T) {
	t.Cleanup(xdg.Reload)

	// fake XDG paths
	t.Setenv("HOME", t.TempDir())
	xdg.Reload()

	provider := client.NewKeyProvider("test/keys")

	key, err := provider.GenerateKey("testapp", "john@example.com", "Linux")
	require.NoError(t, err)

	assert.True(t, key.IsPrivate())

	path, err := provider.WriteKey(key)
	require.NoError(t, err)

	t.Logf("saved key to %s", path)

	k, err := provider.ReadValidKey("testapp", "john@example.com")
	require.NoError(t, err)

	assert.True(t, k.IsPrivate())

	err = provider.DeleteKey("testapp", "john@example.com")
	require.NoError(t, err)

	_, err = provider.ReadValidKey("testapp", "john@example.com")
	require.Error(t, err)
}
