// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package plain contains the logic related to the plain key management.
package plain

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key is the plain key.
type Key interface {
	Verify(data, signature []byte) error
	ID() string
}

// ParseKey creates a key from the PEM encoded data.
func ParseKey(data []byte) (Key, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if k, ok := key.(*ecdsa.PublicKey); ok {
		return NewEcdsaKey(k)
	}

	return nil, fmt.Errorf("unsupported key type %#v", key)
}
