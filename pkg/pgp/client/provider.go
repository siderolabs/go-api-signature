// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/adrg/xdg"

	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

const (
	keyLifetime = 4 * time.Hour
)

// KeyProvider handles loading/saving client keys.
type KeyProvider struct {
	dataFileDirectory string
	keyLifetime       time.Duration
}

// NewKeyProvider creates a new KeyProvider.
func NewKeyProvider(dataFileDirectory string) *KeyProvider {
	return &KeyProvider{
		dataFileDirectory: dataFileDirectory,
		keyLifetime:       keyLifetime,
	}
}

// ReadValidKey reads a PGP key from the filesystem.
//
// If the key is missing or invalid (e.g., expired, revoked), an error will be returned.
func (provider *KeyProvider) ReadValidKey(context, email string) (*Key, error) {
	keyPath, err := provider.getKeyFilePath(context, email)
	if err != nil {
		return nil, err
	}

	keyF, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}

	defer keyF.Close() //nolint:errcheck

	key, err := pgpcrypto.NewKeyFromArmoredReader(keyF)
	if err != nil {
		return nil, err
	}

	pgpKey, err := pgp.NewKey(key)
	if err != nil {
		return nil, err
	}

	err = pgpKey.Validate()
	if err != nil {
		return nil, err
	}

	unlocked, err := pgpKey.IsUnlocked()
	if err != nil {
		return nil, err
	}

	if !unlocked {
		return nil, fmt.Errorf("private key is locked")
	}

	return &Key{
		Key:      pgpKey,
		context:  context,
		identity: email,
	}, nil
}

// GenerateKey generates a new PGP key pair.
func (provider *KeyProvider) GenerateKey(context, email, clientNameWithVersion string) (*Key, error) {
	name := clientNameWithVersion
	comment := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	key, err := pgp.GenerateKey(name, comment, email, provider.keyLifetime)
	if err != nil {
		return nil, err
	}

	return &Key{
		Key:      key,
		context:  context,
		identity: email,
	}, nil
}

// DeleteKey deletes the key pair from disk.
func (provider *KeyProvider) DeleteKey(context, email string) error {
	keyPath, err := provider.getKeyFilePath(context, email)
	if err != nil {
		return err
	}

	return os.Remove(keyPath)
}

// WriteKey saves the key pair to disk and returns the save path.
func (provider *KeyProvider) WriteKey(c *Key) (string, error) {
	armored, err := c.Armor()
	if err != nil {
		return "", err
	}

	keyPath, err := provider.getKeyFilePath(c.context, c.identity)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(keyPath, []byte(armored), 0o600)
	if err != nil {
		return "", err
	}

	return keyPath, err
}

func (provider *KeyProvider) getKeyFilePath(context, identity string) (string, error) {
	keyName := fmt.Sprintf("%s-%s.pgp", context, identity)

	return xdg.DataFile(filepath.Join(provider.dataFileDirectory, keyName))
}
