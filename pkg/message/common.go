// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// SignatureHeaderKey is the header name for the signature.
	SignatureHeaderKey = "x-sidero-signature"

	// TimestampHeaderKey is the header name for the timestamp.
	TimestampHeaderKey = "x-sidero-timestamp"

	// PayloadHeaderKey is the header name for the signed payload.
	PayloadHeaderKey = "x-sidero-payload"

	// AuthorizationHeaderKey is Authorization: header name.
	AuthorizationHeaderKey = "authorization"

	// BearerPrefix is the prefix for the Authorization: header value.
	BearerPrefix = "Bearer "

	timestampAllowedSkew = 5 * time.Minute
)

// Well-known metadata keys which should be verified.
const (
	NodesHeaderKey          = "nodes"
	SelectorsHeaderKey      = "selectors"
	FieldSelectorsHeaderKey = "fieldSelectors"
	RuntimeHeaderHey        = "runtime"
	ContextHeaderKey        = "context"
	ClusterHeaderKey        = "cluster"
	NamespaceHeaderKey      = "namespace"
	UIDHeaderKey            = "uid"
)

// ErrNotFound is returned when a metadata header is not found.
var ErrNotFound = errors.New("not found")

func parseTimestamp(value string) (*time.Time, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, TimestampHeaderKey)
	}

	timestampInt, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, err
	}

	timestamp := time.Unix(timestampInt, 0)

	return &timestamp, nil
}

func parseSignature(value string) (*Signature, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, SignatureHeaderKey)
	}

	signatureParts := strings.Split(value, " ")
	if len(signatureParts) == 0 {
		return nil, fmt.Errorf("invalid signature header: %s", value)
	}

	if signatureParts[0] != string(SignatureVersionV1) {
		return nil, fmt.Errorf("unsupported signature version: %s", signatureParts[0])
	}

	signature, err := base64.StdEncoding.DecodeString(signatureParts[3])
	if err != nil {
		return nil, err
	}

	return &Signature{
		Signature:      signature,
		Identity:       signatureParts[1],
		KeyFingerprint: signatureParts[2],
	}, nil
}

func verifyTimestamp(timestamp *time.Time) error {
	if time.Now().Add(timestampAllowedSkew).Before(*timestamp) ||
		time.Now().Add(-timestampAllowedSkew).After(*timestamp) {
		return fmt.Errorf("timestamp is outside of allowed skew: %s", timestamp)
	}

	return nil
}
