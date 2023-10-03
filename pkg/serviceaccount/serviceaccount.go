// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package serviceaccount contains service accounts related logic.
package serviceaccount

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

const (
	// SideroServiceAccountKeyEnvVar is the name of the environment variable
	// that contains the base64-encoded service account key JSON.
	SideroServiceAccountKeyEnvVar = "SIDERO_SERVICE_ACCOUNT_KEY"

	// OmniServiceAccountKeyEnvVar is the name of the environment variable
	// that contains the base64-encoded service account key JSON.
	OmniServiceAccountKeyEnvVar = "OMNI_SERVICE_ACCOUNT_KEY"
)

// JSON is the JSON representation of a service account.
type JSON struct {
	// Name is the name (identity) of the service account.
	Name string `json:"name"`

	// PGPKey is the armored PGP private key of the service account.
	PGPKey string `json:"pgp_key"`
}

// ServiceAccount represents a service account with an identity and a pgp key.
type ServiceAccount struct {
	Key  *pgp.Key
	Name string
}

// GetFromEnv checks if a service account is available in the environment variables.
// If a known environment variable is found, its name and value are returned.
func GetFromEnv() (envKey, valueBase64 string) {
	for _, alias := range []string{SideroServiceAccountKeyEnvVar, OmniServiceAccountKeyEnvVar} {
		value, valueOk := os.LookupEnv(alias)
		if !valueOk {
			continue
		}

		return alias, value
	}

	return "", ""
}

// Encode encodes the given service account name and pgp key into a base64 encoded JSON string.
func Encode(name string, key *pgp.Key) (string, error) {
	armoredPrivateKey, err := key.Armor()
	if err != nil {
		return "", fmt.Errorf("failed to armor private key: %w", err)
	}

	saKey := JSON{
		Name:   name,
		PGPKey: armoredPrivateKey,
	}

	saKeyJSON, err := json.Marshal(saKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(saKeyJSON), nil
}

// Decode parses and decodes a service account from a base64 encoded JSON string.
func Decode(valueBase64 string) (*ServiceAccount, error) {
	saJSON, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		return nil, err
	}

	var sa JSON

	err = json.Unmarshal(saJSON, &sa)
	if err != nil {
		return nil, err
	}

	cryptoKey, err := pgpcrypto.NewKeyFromArmored(sa.PGPKey)
	if err != nil {
		return nil, err
	}

	key, err := pgp.NewKey(cryptoKey)
	if err != nil {
		return nil, err
	}

	return &ServiceAccount{
		Name: sa.Name,
		Key:  key,
	}, nil
}
