// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package pgp contains the logic related to the PGP key management.
package pgp

import (
	"crypto"
	"fmt"
	"net/mail"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
)

const (
	maxAllowedLifetime = 8 * time.Hour
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

// Armor returns the key in the armored format.
func (p *Key) Armor() (string, error) {
	return p.key.Armor()
}

// ArmorPublic returns only the public key in armored format.
func (p *Key) ArmorPublic() (string, error) {
	return p.key.GetArmoredPublicKey()
}

// Validate validates the key.
func (p *Key) Validate() error {
	if p.key.IsRevoked() {
		return fmt.Errorf("key is revoked")
	}

	if p.key.IsExpired() {
		return fmt.Errorf("key is expired")
	}

	entity := p.key.GetEntity()
	if entity == nil {
		return fmt.Errorf("key does not contain an entity")
	}

	identity := entity.PrimaryIdentity()
	if identity == nil {
		return fmt.Errorf("key does not contain a primary identity")
	}

	_, err := mail.ParseAddress(identity.Name)
	if err != nil {
		return fmt.Errorf("key does not contain a valid email address: %w: %s", err, identity.Name)
	}

	return p.validateLifetime()
}

func (p *Key) validateLifetime() error {
	entity := p.key.GetEntity()
	identity := entity.PrimaryIdentity()
	sig := identity.SelfSignature

	if sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs == 0 {
		return fmt.Errorf("key does not contain a valid key lifetime")
	}

	expiration := time.Now().Add(maxAllowedLifetime)

	if !entity.PrimaryKey.KeyExpired(sig, expiration) {
		return fmt.Errorf("key lifetime is too long: %s", time.Duration(*sig.KeyLifetimeSecs)*time.Second)
	}

	return nil
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

	newEntity, err := openpgp.NewEntity(name, comment, email, cfg)
	if err != nil {
		return nil, err
	}

	return newEntity, nil
}
