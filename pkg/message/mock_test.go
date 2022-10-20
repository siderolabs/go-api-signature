// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type mockSignerVerifier struct{}

func (mock mockSignerVerifier) Fingerprint() string {
	return "mock-fingerprint"
}

func (mock mockSignerVerifier) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	return []byte(hex.EncodeToString(hash[:])), nil
}

func (mock mockSignerVerifier) Verify(data, signature []byte) error {
	expected, _ := mock.Sign(data) //nolint:errcheck

	if !bytes.Equal(signature, expected) {
		return errors.New("invalid signature")
	}

	return nil
}
