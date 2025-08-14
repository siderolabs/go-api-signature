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

	"github.com/siderolabs/go-api-signature/pkg/fileutils"
	"github.com/siderolabs/go-api-signature/pkg/pgp"
)

const (
	keyLifetime = 4 * time.Hour
)

// KeyProvider handles loading/saving client keys.
type KeyProvider struct {
	// dataFileDirectory is the directory where keys are stored while XDG_DATA_HOME is used as base directory.
	dataFileDirectory string
	// customDataFileDirectory is the directory where keys are stored if custom option is preferred over XDG.
	customDataFileDirectory string
	// customBaseDirectory is the base directory to use if custom option is preferred over XDG.
	customBaseDirectory string
	keyLifetime         time.Duration
	withFallback        bool
	preferCustomOverXDG bool
}

// NewKeyProvider creates a new KeyProvider.
func NewKeyProvider(dataFileDirectory string) *KeyProvider {
	return &KeyProvider{
		dataFileDirectory:       dataFileDirectory,
		keyLifetime:             keyLifetime,
		customDataFileDirectory: dataFileDirectory,
		customBaseDirectory:     xdg.DataHome,
		preferCustomOverXDG:     false,
		withFallback:            false,
	}
}

// NewKeyProviderWithFallback creates a new KeyProvider with fallback option to a custom directory over XDG.
func NewKeyProviderWithFallback(dataFileDirectory, customBaseDirectory, customDataFileDirectory string, preferCustomOverXDG bool) *KeyProvider {
	return &KeyProvider{
		dataFileDirectory:       dataFileDirectory,
		keyLifetime:             keyLifetime,
		customBaseDirectory:     customBaseDirectory,
		customDataFileDirectory: customDataFileDirectory,
		preferCustomOverXDG:     preferCustomOverXDG,
		withFallback:            true,
	}
}

// ReadValidKey reads a PGP key from the filesystem.
//
// If the key is missing or invalid (e.g., expired, revoked), an error will be returned.
func (provider *KeyProvider) ReadValidKey(context, email string) (*Key, error) {
	keyPath, err := provider.getKeyFilePath(context, email, READ)
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
	keyPath, err := provider.getKeyFilePath(context, email, DELETE)
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

	keyPath, err := provider.getKeyFilePath(c.context, c.identity, WRITE)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(keyPath, []byte(armored), 0o600)
	if err != nil {
		return "", err
	}

	return keyPath, err
}

type accessType int32

const (
	READ accessType = iota
	WRITE
	DELETE
)

func (provider *KeyProvider) getKeyFilePath(context, identity string, access accessType) (string, error) {
	keyName := fmt.Sprintf("%s-%s.pgp", context, identity)

	if !provider.withFallback {
		if !provider.preferCustomOverXDG {
			return xdg.DataFile(filepath.Join(provider.dataFileDirectory, keyName))
		}

		return provider.ensureCustomPath(keyName)
	}

	// For Read and Delete operations, regardless of preferred location, if using primary location will result in
	// failure, then use secondary location. If fallback doesn't succeed, then fail using primary location.
	//
	// For Write operation, if preferred location is Custom, do not fall back to XDG upon failure.
	if access == READ || access == DELETE {
		xdgExists := fileutils.FileExists(filepath.Join(xdg.DataHome, provider.dataFileDirectory, keyName))
		customExists := fileutils.FileExists(filepath.Join(provider.customBaseDirectory, provider.customDataFileDirectory, keyName))

		if !provider.preferCustomOverXDG {
			if !xdgExists && customExists {
				return provider.ensureCustomPath(keyName)
			}

			return xdg.DataFile(filepath.Join(provider.dataFileDirectory, keyName))
		}

		if xdgExists && !customExists {
			return xdg.DataFile(filepath.Join(provider.dataFileDirectory, keyName))
		}

		return provider.ensureCustomPath(keyName)
	}

	if !provider.preferCustomOverXDG && fileutils.IsWritable(filepath.Join(xdg.DataHome, provider.dataFileDirectory)) {
		return xdg.DataFile(filepath.Join(provider.dataFileDirectory, keyName))
	}

	return provider.ensureCustomPath(keyName)
}

func (provider *KeyProvider) ensureCustomPath(keyName string) (string, error) {
	basePath := filepath.Join(provider.customBaseDirectory, provider.customDataFileDirectory)
	fullPath := filepath.Join(basePath, keyName)

	err := os.MkdirAll(basePath, os.ModeDir|0o700)
	if err != nil {
		return "", err
	}

	return fullPath, nil
}
