// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package pgp contains the logic related to the PGP key management.
package pgp

import (
	"crypto"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Key represents a PGP key. It can be a public key or a private & public key pair.
type Key struct {
	key     *pgpcrypto.Key
	keyring *pgpcrypto.KeyRing
}

// GenerateKey generates a new PGP key pair.
func GenerateKey(name, comment, email string, lifetime time.Duration) (*Key, error) {
	entity, err := generateEntity(name, comment, email, uint32(lifetime/time.Second))
	if err != nil {
		return nil, err
	}

	key, err := pgpcrypto.NewKeyFromEntity(entity)
	if err != nil {
		return nil, err
	}

	return NewKey(key)
}

// NewKey returns a new PGP key from the given pgpcrypto.Key.
func NewKey(key *pgpcrypto.Key) (*Key, error) {
	keyRing, err := pgpcrypto.NewKeyRing(key)
	if err != nil {
		return nil, err
	}

	return &Key{
		key:     key,
		keyring: keyRing,
	}, nil
}

// Fingerprint returns the fingerprint of the key.
func (p *Key) Fingerprint() string {
	return p.key.GetFingerprint()
}

// Verify verifies the signature of the given data using the public key.
func (p *Key) Verify(data, signature []byte) error {
	message := pgpcrypto.NewPlainMessage(data)

	sig := pgpcrypto.NewPGPSignature(signature)

	return p.keyring.VerifyDetached(message, sig, pgpcrypto.GetUnixTime())
}

// Sign signs the given data using the private key.
func (p *Key) Sign(data []byte) ([]byte, error) {
	message := pgpcrypto.NewPlainMessage(data)

	signature, err := p.keyring.SignDetached(message)
	if err != nil {
		return nil, err
	}

	return signature.GetBinary(), nil
}

// IsPrivate returns true if the key contains a private key.
func (p *Key) IsPrivate() bool {
	return p.key.IsPrivate()
}

// IsUnlocked returns true if the private key is unlocked.
func (p *Key) IsUnlocked() (bool, error) {
	return p.key.IsUnlocked()
}

// Armor returns the key in the armored format.
func (p *Key) Armor() (string, error) {
	return p.key.Armor()
}

// ArmorPublic returns only the public key in armored format.
func (p *Key) ArmorPublic() (string, error) {
	return p.key.GetArmoredPublicKey()
}

// IsExpired returns true if the key is expired with clock skew.
func (p *Key) IsExpired(clockSkew time.Duration) bool {
	if clockSkew < 0 {
		panic("clock skew can't be negative")
	}

	now := time.Now()

	i := p.key.GetEntity().PrimaryIdentity()
	keyLifetimeSecs := i.SelfSignature.KeyLifetimeSecs

	if keyLifetimeSecs != nil && *keyLifetimeSecs < uint32(clockSkew/time.Second) {
		// if the key is short-lived, limit clock skew to the half of the key lifetime
		clockSkew = time.Duration(*keyLifetimeSecs) * time.Second / 2
	}

	expired := func(t time.Time) bool {
		return p.key.GetEntity().PrimaryKey.KeyExpired(i.SelfSignature, t) || // primary key has expired
			i.SelfSignature.SigExpired(t) // user ID self-signature has expired
	}

	return expired(now.Add(clockSkew)) && expired(now.Add(-clockSkew))
}

// generateEntity generates a new PGP entity.
// Adapted from crypto.generateKey to be able to set the expiration.
func generateEntity(name, comment, email string, lifetimeSecs uint32) (*openpgp.Entity, error) {
	cfg := &packet.Config{
		Algorithm:              packet.PubKeyAlgoEdDSA,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        lifetimeSecs,
		SigLifetimeSecs:        lifetimeSecs,
	}

	return openpgp.NewEntity(name, comment, email, cfg)
}
