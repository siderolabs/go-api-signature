// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package plain

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// EcdsaKey represents a public ecdsa key.
type EcdsaKey struct {
	key *ecdsa.PublicKey
	id  string
}

// NewEcdsaKey returns a new EcdsaKey.
func NewEcdsaKey(key *ecdsa.PublicKey) (*EcdsaKey, error) {
	publicKeyBytes, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	if _, err = hasher.Write(publicKeyBytes); err != nil {
		return nil, err
	}

	return &EcdsaKey{
		key: key,
		id:  base64.URLEncoding.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// ID returns the fingerprint of the key.
func (p *EcdsaKey) ID() string {
	return p.id
}

// Verify verifies the signature of the given data using the public key.
// This method expects signature to be in r||s format, not DER encoded.
func (p *EcdsaKey) Verify(data, signature []byte) error {
	hash := sha256.Sum256(data)

	sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return errors.New("missing valid signature")
	}

	if len(sigBytes)%2 != 0 {
		return errors.New("missing valid signature")
	}

	half := len(sigBytes) / 2

	r := new(big.Int).SetBytes(sigBytes[:half])
	s := new(big.Int).SetBytes(sigBytes[half:])

	if !ecdsa.Verify(p.key, hash[:], r, s) {
		return errors.New("missing valid signature")
	}

	return nil
}
