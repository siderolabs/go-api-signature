// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pgp

import (
	"fmt"
	"net/mail"
	"time"
)

// Key validation defaults.
const (
	DefaultMaxAllowedLifetime = 8 * time.Hour
	DefaultAllowedClockSkew   = 5 * time.Minute
	DefaultValidEmailAsName   = true
)

type validationOptions struct {
	maxAllowedLifetime time.Duration
	validEmailAsName   bool
	allowedClockSkew   time.Duration
}

func newDefaultValidationOptions() validationOptions {
	return validationOptions{
		maxAllowedLifetime: DefaultMaxAllowedLifetime,
		allowedClockSkew:   DefaultAllowedClockSkew,
		validEmailAsName:   DefaultValidEmailAsName,
	}
}

// ValidationOption represents a functional validation option.
type ValidationOption func(*validationOptions)

// WithMaxAllowedLifetime customizes the max allowed key lifetime in the validation.
func WithMaxAllowedLifetime(maxAllowedLifetime time.Duration) ValidationOption {
	return func(o *validationOptions) {
		o.maxAllowedLifetime = maxAllowedLifetime
	}
}

// WithValidEmailAsName sets whether the validation should be performed on the name to be a valid email address.
func WithValidEmailAsName(validEmailAsName bool) ValidationOption {
	return func(o *validationOptions) {
		o.validEmailAsName = validEmailAsName
	}
}

// WithAllowedClockSkew sets the allowed clock skew in the key expiration validation.
func WithAllowedClockSkew(allowedClockSkew time.Duration) ValidationOption {
	return func(o *validationOptions) {
		o.allowedClockSkew = allowedClockSkew
	}
}

// Validate validates the key.
func (p *Key) Validate(opt ...ValidationOption) error {
	options := newDefaultValidationOptions()

	for _, o := range opt {
		o(&options)
	}

	if p.key.IsRevoked() {
		return fmt.Errorf("key is revoked")
	}

	entity := p.key.GetEntity()
	if entity == nil {
		return fmt.Errorf("key does not contain an entity")
	}

	identity := entity.PrimaryIdentity()
	if identity == nil {
		return fmt.Errorf("key does not contain a primary identity")
	}

	if p.IsExpired(options.allowedClockSkew) {
		return fmt.Errorf("key expired")
	}

	if options.validEmailAsName {
		_, err := mail.ParseAddress(identity.Name)
		if err != nil {
			return fmt.Errorf("key does not contain a valid email address: %w: %s", err, identity.Name)
		}
	}

	return p.validateLifetime(&options)
}

func (p *Key) validateLifetime(opts *validationOptions) error {
	entity := p.key.GetEntity()
	identity := entity.PrimaryIdentity()
	sig := identity.SelfSignature

	if sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs == 0 {
		return fmt.Errorf("key does not contain a valid key lifetime")
	}

	// We don't care when the key was created, only when it expires relative to the server "now" time.
	//
	// Also add one minute to account for rounding errors or time skew.
	expiration := time.Now().Add(opts.maxAllowedLifetime + time.Minute)

	if !entity.PrimaryKey.KeyExpired(sig, expiration) {
		return fmt.Errorf("key lifetime is too long: %s", time.Duration(*sig.KeyLifetimeSecs)*time.Second)
	}

	return nil
}
