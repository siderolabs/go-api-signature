// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message

// SignatureVersion represents the version of the signature in GRPC metadata.
type SignatureVersion string

// SignatureVersionV1 is the signature version v1.
const SignatureVersionV1 SignatureVersion = "siderov1"

// Signer is a signer of a GRPC request, e.g. a PGP private key.
type Signer interface {
	Fingerprint() string
	Sign(data []byte) ([]byte, error)
}

// SignatureVerifier is a verifier of a GRPC request signature, e.g. a PGP public key.
type SignatureVerifier interface {
	Verify(data, signature []byte) error
}

// Signature represents a GRPC signature version 1.
type Signature struct {
	Identity       string
	KeyFingerprint string
	Signature      []byte
}
