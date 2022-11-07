// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pgp_test

import (
	"crypto"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
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

func genKey(t *testing.T, lifetimeSecs uint32, now func() time.Time) *pgp.Key {
	cfg := &packet.Config{
		Algorithm:              packet.PubKeyAlgoEdDSA,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        lifetimeSecs,
		SigLifetimeSecs:        lifetimeSecs,
		Time:                   now,
	}

	entity, err := openpgp.NewEntity("test", "test", "keytest@example.com", cfg)
	require.NoError(t, err)

	key, err := pgpcrypto.NewKeyFromEntity(entity)
	require.NoError(t, err)

	pgpKey, err := pgp.NewKey(key)
	require.NoError(t, err)

	return pgpKey
}

func TestKeyExpiration(t *testing.T) {
	for _, tt := range []struct { //nolint:govet
		name          string
		lifetime      time.Duration
		shift         time.Duration
		expectedError string
	}{
		{
			name:          "no expiration",
			expectedError: "key does not contain a valid key lifetime",
		},
		{
			name:          "expiration too long",
			lifetime:      pgp.MaxAllowedLifetime + 1*time.Hour,
			expectedError: "key lifetime is too long: 9h0m0s",
		},
		{
			name:          "generated in the future",
			lifetime:      pgp.MaxAllowedLifetime / 2,
			shift:         pgp.AllowedClockSkew * 2,
			expectedError: "key expired",
		},
		{
			name:          "already expired",
			lifetime:      pgp.MaxAllowedLifetime / 2,
			shift:         -pgp.AllowedClockSkew*2 - pgp.MaxAllowedLifetime/2,
			expectedError: "key expired",
		},
		{
			name:     "within clock skew -",
			lifetime: pgp.MaxAllowedLifetime / 2,
			shift:    -pgp.AllowedClockSkew / 2,
		},
		{
			name:     "within clock skew +",
			lifetime: pgp.MaxAllowedLifetime / 2,
			shift:    pgp.AllowedClockSkew / 2,
		},
		{
			name:     "short-lived key",
			lifetime: pgp.AllowedClockSkew / 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := genKey(t, uint32(tt.lifetime/time.Second), func() time.Time {
				return time.Now().Add(tt.shift)
			})

			err := key.Validate()

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
