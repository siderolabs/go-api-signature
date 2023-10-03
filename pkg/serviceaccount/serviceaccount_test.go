// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package serviceaccount_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/pgp"
	"github.com/siderolabs/go-api-signature/pkg/serviceaccount"
)

func TestEncodeDecode(t *testing.T) {
	key, err := pgp.GenerateKey("test-name-1", "test-comment-1", "test-1@sa.sidero.dev", 24*time.Hour)
	require.NoError(t, err)

	encoded, err := serviceaccount.Encode("bla", key)
	require.NoError(t, err)

	decoded, err := serviceaccount.Decode(encoded)
	require.NoError(t, err)

	assert.Equal(t, "bla", decoded.Name)
	assert.Equal(t, key.Fingerprint(), decoded.Key.Fingerprint())
}

func TestEnv(t *testing.T) {
	key1, err := pgp.GenerateKey("test-name-1", "test-comment-1", "test-1@sa.sidero.dev", 24*time.Hour)
	require.NoError(t, err)

	key1Encoded, err := serviceaccount.Encode("bla1", key1)
	require.NoError(t, err)

	t.Setenv(serviceaccount.SideroServiceAccountKeyEnvVar, key1Encoded)

	key2, err := pgp.GenerateKey("test-name-2", "test-comment-2", "test-2@sa.sidero.dev", 24*time.Hour)
	require.NoError(t, err)

	key2Encoded, err := serviceaccount.Encode("bla2", key2)
	require.NoError(t, err)

	t.Setenv(serviceaccount.OmniServiceAccountKeyEnvVar, key2Encoded)

	// both env vars are set, SideroServiceAccountKeyEnvVar should take precedence
	envKey, valueBase64 := serviceaccount.GetFromEnv()
	assert.Equal(t, serviceaccount.SideroServiceAccountKeyEnvVar, envKey)
	assert.Equal(t, key1Encoded, valueBase64)

	require.NoError(t, os.Unsetenv(serviceaccount.SideroServiceAccountKeyEnvVar))

	// only OmniServiceAccountKeyEnvVar is set
	envKey, valueBase64 = serviceaccount.GetFromEnv()
	assert.Equal(t, serviceaccount.OmniServiceAccountKeyEnvVar, envKey)
	assert.Equal(t, key2Encoded, valueBase64)

	require.NoError(t, os.Unsetenv(serviceaccount.OmniServiceAccountKeyEnvVar))

	// no env vars are set
	envKey, valueBase64 = serviceaccount.GetFromEnv()
	assert.Empty(t, envKey)
	assert.Empty(t, valueBase64)
}
