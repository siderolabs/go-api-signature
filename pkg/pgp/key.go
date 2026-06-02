// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package pgp contains the logic related to the PGP key management.
package pgp

import (
	"crypto"
	"math"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Key represents a PGP key. It can be a public key or a private & public key pair.
type Key struct {
	key     *pgpcrypto.Key
	keyring *pgpcrypto.KeyRing
	mu      sync.Mutex
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
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.key.GetFingerprint()
}

// Verify verifies the signature of the given data using the public key.
// NB: we do not expect/validate the timestamp inside the signature.
// Timestamp validation is deferred to the library using the module.
// It can be stored in the signed payload.
func (p *Key) Verify(data, signature []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if err, isSignatureError := p.verify(data, signature, now.Unix()); err == nil {
		return nil
	} else if !isSignatureError {
		return err
	}

	clockSkew := DefaultAllowedClockSkew.Seconds()

	// Pass zero time to read the lifetime before retrying with clock skew.
	if sig, _ := p.primaryIdentity(time.Time{}); sig != nil && sig.KeyLifetimeSecs != nil {
		clockSkew = math.Min(float64(*sig.KeyLifetimeSecs)/2, clockSkew)
	}

	err, _ := p.verify(data, signature, now.Add(time.Duration(clockSkew)*time.Second).Unix())

	return err
}

// Sign signs the given data using the private key.
func (p *Key) Sign(data []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	signer, err := pgpcrypto.PGP().Sign().SigningKeys(p.keyring).Detached().New()
	if err != nil {
		return nil, err
	}

	return signer.Sign(data, pgpcrypto.Bytes)
}

// IsPrivate returns true if the key contains a private key.
func (p *Key) IsPrivate() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.key.IsPrivate()
}

// IsUnlocked returns true if the private key is unlocked.
func (p *Key) IsUnlocked() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.key.IsUnlocked()
}

// Armor returns the key in the armored format.
func (p *Key) Armor() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.key.Armor()
}

// ArmorPublic returns only the public key in armored format.
func (p *Key) ArmorPublic() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.key.GetArmoredPublicKey()
}

// IsExpired returns true if the key is expired with clock skew.
func (p *Key) IsExpired(clockSkew time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.isExpired(clockSkew)
}

func (p *Key) isExpired(clockSkew time.Duration) bool {
	if clockSkew < 0 {
		panic("clock skew can't be negative")
	}

	now := time.Now()

	// Pass zero time to read lifetime without doing time checks - expiration is evaluated below with skew.
	sig, _ := p.primaryIdentity(time.Time{})
	if sig == nil {
		return true
	}

	if keyLifetimeSecs := sig.KeyLifetimeSecs; keyLifetimeSecs != nil && *keyLifetimeSecs < uint32(clockSkew/time.Second) {
		// if the key is short-lived, limit clock skew to the half of the key lifetime
		clockSkew = time.Duration(*keyLifetimeSecs) * time.Second / 2
	}

	expired := func(t time.Time) bool {
		sig, _ := p.primaryIdentity(t)
		if sig == nil {
			return true
		}

		return p.key.GetEntity().PrimaryKey.KeyExpired(sig, t) || // primary key has expired
			sig.SigExpired(t) // user ID self-signature has expired
	}

	return expired(now.Add(clockSkew)) && expired(now.Add(-clockSkew))
}

func (p *Key) verify(data, signature []byte, unixTime int64) (error, bool) {
	verifier, err := pgpcrypto.PGP().Verify().VerificationKeys(p.keyring).VerifyTime(unixTime).New()
	if err != nil {
		return err, false
	}

	result, err := verifier.VerifyDetached(data, signature, pgpcrypto.Bytes)
	if err != nil {
		return err, false
	}

	if err = result.SignatureError(); err != nil {
		return err, true
	}

	return nil, false
}

func (p *Key) primaryIdentity(at time.Time) (*packet.Signature, *openpgp.Identity) {
	entity := p.key.GetEntity()
	if entity == nil {
		return nil, nil
	}

	return entity.PrimaryIdentity(at, &packet.Config{})
}

func (p *Key) isRevoked(at time.Time) bool {
	entity := p.key.GetEntity()
	if entity == nil {
		return false
	}

	if entity.Revoked(at) {
		return true
	}

	sig, identity := p.preferredIdentityIgnoringRevocation()
	if identity == nil {
		return false
	}

	return identity.Revoked(sig, at, &packet.Config{})
}

func (p *Key) preferredIdentityIgnoringRevocation() (*packet.Signature, *openpgp.Identity) {
	entity := p.key.GetEntity()
	if entity == nil {
		return nil, nil
	}

	var (
		selectedIdentity *openpgp.Identity
		selectedSig      *packet.Signature
	)

	cfg := &packet.Config{}

	for _, identity := range entity.Identities {
		// Zero time ignores expiry while selecting the identity for revocation checks.
		sig, err := identity.LatestValidSelfCertification(time.Time{}, cfg)
		if err != nil {
			continue
		}

		if shouldPreferIdentity(selectedIdentity, selectedSig, identity, sig) {
			selectedIdentity = identity
			selectedSig = sig
		}
	}

	return selectedSig, selectedIdentity
}

func shouldPreferIdentity(existingIdentity *openpgp.Identity, existingSig *packet.Signature, nextIdentity *openpgp.Identity, nextSig *packet.Signature) bool {
	if existingIdentity == nil {
		return true
	}

	if len(existingIdentity.Revocations) > len(nextIdentity.Revocations) {
		return true
	}

	if len(existingIdentity.Revocations) < len(nextIdentity.Revocations) {
		return false
	}

	if existingSig.IsPrimaryId != nil && *existingSig.IsPrimaryId &&
		(nextSig.IsPrimaryId == nil || !*nextSig.IsPrimaryId) {
		return false
	}

	if (existingSig.IsPrimaryId == nil || !*existingSig.IsPrimaryId) &&
		nextSig.IsPrimaryId != nil && *nextSig.IsPrimaryId {
		return true
	}

	return nextSig.CreationTime.After(existingSig.CreationTime)
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
