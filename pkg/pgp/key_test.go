// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pgp_test

import (
	"crypto"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

func TestKeyFlow(t *testing.T) {
	key, err := pgp.GenerateKey("John Smith", "Linux", "john.smith@example.com", time.Hour)
	require.NoError(t, err)

	testKeyFlow(t, key)
}

func TestPublicKeyVerifiesDetachedSignature(t *testing.T) {
	key, err := pgp.GenerateKey("John Smith", "Linux", "john.smith@example.com", time.Hour)
	require.NoError(t, err)

	publicKeyArmored, err := key.ArmorPublic()
	require.NoError(t, err)

	publicKey, err := pgpcrypto.NewKeyFromArmored(publicKeyArmored)
	require.NoError(t, err)

	verifier, err := pgp.NewKey(publicKey)
	require.NoError(t, err)
	assert.False(t, verifier.IsPrivate())

	message := []byte("Hello, World!")

	signature, err := key.Sign(message)
	require.NoError(t, err)

	assert.NoError(t, verifier.Verify(message, signature))
}

func testKeyFlow(t *testing.T, key *pgp.Key) {
	assert.True(t, key.IsPrivate())
	assert.NoError(t, key.Validate())

	message := []byte("Hello, World!")

	signature, err := key.Sign(message)
	require.NoError(t, err)

	assert.NoError(t, key.Verify(message, signature))
	assert.Error(t, key.Verify(message[:len(message)-1], signature))
	assert.Error(t, key.Verify(message, signature[:len(signature)-1]))
}

func TestTimeSkew(t *testing.T) {
	start := time.Now()

	key, err := pgp.GenerateKey("John Smith", "Linux", "john.smith@example.com", time.Hour)
	require.NoError(t, err)

	assert.True(t, key.IsPrivate())
	assert.NoError(t, key.Validate())

	message := []byte("Hello, World!")

	signature, err := key.Sign(message)
	require.NoError(t, err)

	assert.NoError(t, key.Verify(message, signature))

	signature = signAt(t, key, message, start.Add(time.Minute))

	assert.NoError(t, key.Verify(message, signature))
}

func signAt(t *testing.T, key *pgp.Key, message []byte, at time.Time) []byte {
	t.Helper()

	rawKey, err := pgpcrypto.NewKeyFromArmored(requireArmored(t, key))
	require.NoError(t, err)

	signer, err := pgpcrypto.PGP().Sign().SigningKey(rawKey).Detached().SignTime(at.Unix()).New()
	require.NoError(t, err)

	signature, err := signer.Sign(message, pgpcrypto.Bytes)
	require.NoError(t, err)

	return signature
}

func requireArmored(t *testing.T, key *pgp.Key) string {
	t.Helper()

	armored, err := key.Armor()
	require.NoError(t, err)

	return armored
}

func genKey(t *testing.T, lifetimeSecs uint32, email string, now func() time.Time) *pgp.Key {
	cfg := &packet.Config{
		Algorithm:              packet.PubKeyAlgoEdDSA,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        lifetimeSecs,
		SigLifetimeSecs:        lifetimeSecs,
		Time:                   now,
	}

	entity, err := openpgp.NewEntity("test", "test", email, cfg)
	require.NoError(t, err)

	key, err := pgpcrypto.NewKeyFromEntity(entity)
	require.NoError(t, err)

	pgpKey, err := pgp.NewKey(key)
	require.NoError(t, err)

	return pgpKey
}

func TestKeyValidation(t *testing.T) {
	for _, tt := range []struct { //nolint:govet
		name          string
		lifetime      time.Duration
		shift         time.Duration
		expectedError string
		email         string
		opts          []pgp.ValidationOption
	}{
		{
			name:          "no expiration",
			email:         "keytest@example.com",
			expectedError: "key does not contain a valid key lifetime",
		},
		{
			name:          "expiration too long",
			email:         "keytest@example.com",
			lifetime:      pgp.DefaultMaxAllowedLifetime + 1*time.Hour,
			expectedError: "key lifetime is too long: 9h0m0s",
		},
		{
			name:          "generated in the future",
			email:         "keytest@example.com",
			lifetime:      pgp.DefaultMaxAllowedLifetime / 2,
			shift:         pgp.DefaultAllowedClockSkew * 2,
			expectedError: "key expired",
		},
		{
			name:     "generated in the future - custom skew validation",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultMaxAllowedLifetime / 2,
			shift:    pgp.DefaultAllowedClockSkew * 2,
			opts: []pgp.ValidationOption{
				pgp.WithAllowedClockSkew(pgp.DefaultAllowedClockSkew * 3),
			},
		},
		{
			name:          "already expired",
			email:         "keytest@example.com",
			lifetime:      pgp.DefaultMaxAllowedLifetime / 2,
			shift:         -pgp.DefaultAllowedClockSkew*2 - pgp.DefaultMaxAllowedLifetime/2,
			expectedError: "key expired",
		},
		{
			name:     "within clock skew -",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultMaxAllowedLifetime / 2,
			shift:    -pgp.DefaultAllowedClockSkew / 2,
		},
		{
			name:     "within clock skew +",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultMaxAllowedLifetime / 2,
			shift:    pgp.DefaultAllowedClockSkew / 2,
		},
		{
			name:     "short-lived key",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultAllowedClockSkew / 2,
		},
		{
			name:     "short-lived key generated within limited clock skew",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultAllowedClockSkew / 2,
			shift:    pgp.DefaultAllowedClockSkew / 5,
		},
		{
			name:          "short-lived key generated beyond limited clock skew",
			email:         "keytest@example.com",
			lifetime:      pgp.DefaultAllowedClockSkew / 2,
			shift:         pgp.DefaultAllowedClockSkew / 2,
			expectedError: "key expired",
		},
		{
			name:     "long-lived key - custom lifetime validation",
			email:    "keytest@example.com",
			lifetime: 30 * 24 * time.Hour,
			opts: []pgp.ValidationOption{
				pgp.WithMaxAllowedLifetime(31 * 24 * time.Hour),
			},
		},
		{
			name:          "invalid email",
			email:         "invalid",
			lifetime:      pgp.DefaultMaxAllowedLifetime / 2,
			expectedError: "key does not contain a valid email address: mail: missing @ in addr-spec: test (test) <invalid>",
		},
		{
			name:     "invalid email - skipped validation",
			email:    "invalid",
			lifetime: pgp.DefaultMaxAllowedLifetime / 2,
			opts: []pgp.ValidationOption{
				pgp.WithValidEmailAsName(false),
			},
		},
		{
			name:     "should be ok",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultMaxAllowedLifetime,
		},
		{
			name:     "should be ok (with time truncation)",
			email:    "keytest@example.com",
			lifetime: pgp.DefaultMaxAllowedLifetime + time.Minute - time.Nanosecond,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := genKey(t, uint32(tt.lifetime/time.Second), tt.email, func() time.Time {
				return time.Now().Add(tt.shift)
			})

			err := key.Validate(tt.opts...)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRevokedKeyValidation(t *testing.T) {
	entity, err := openpgp.NewEntity("test", "test", "keytest@example.com", &packet.Config{
		Algorithm:              packet.PubKeyAlgoEdDSA,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        uint32(time.Hour.Seconds()),
		SigLifetimeSecs:        uint32(time.Hour.Seconds()),
	})
	require.NoError(t, err)

	require.NoError(t, entity.Revoke(packet.NoReason, "test revocation", nil))

	key, err := pgpcrypto.NewKeyFromEntity(entity)
	require.NoError(t, err)

	pgpKey, err := pgp.NewKey(key)
	require.NoError(t, err)

	assert.EqualError(t, pgpKey.Validate(), "key is revoked")
}
