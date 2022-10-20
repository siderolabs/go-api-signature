// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/siderolabs/go-api-signature/pkg/jwt"
)

// GRPC represents a gRPC message.
type GRPC struct {
	Metadata metadata.MD
	Method   string
}

// NewGRPC creates a new GRPC from the given metadata and method.
func NewGRPC(md metadata.MD, method string) *GRPC {
	return &GRPC{
		Metadata: md,
		Method:   method,
	}
}

func (m *GRPC) payload() (*GRPCPayload, error) {
	headerValue := m.firstHeader(PayloadHeaderKey)
	if headerValue == "" {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, PayloadHeaderKey)
	}

	return ParseGRPCPayload([]byte(headerValue))
}

func (m *GRPC) timestamp() (*time.Time, error) {
	return parseTimestamp(m.firstHeader(TimestampHeaderKey))
}

// Signature returns the signature on the message.
func (m *GRPC) Signature() (*Signature, error) {
	return parseSignature(m.firstHeader(SignatureHeaderKey))
}

// JWT returns the JWT on the message.
func (m *GRPC) JWT() (string, error) {
	headerValue := m.firstHeader(AuthorizationHeaderKey)
	if headerValue == "" {
		return "", fmt.Errorf("%w: %s", ErrNotFound, AuthorizationHeaderKey)
	}

	token := strings.TrimPrefix(headerValue, BearerPrefix)

	return token, nil
}

// Sign signs the message with the given signer for SignatureVersionV1.
func (m *GRPC) Sign(identity string, signer Signer) error {
	m.Metadata.Set(TimestampHeaderKey, strconv.FormatInt(time.Now().Unix(), 10))

	// if the request is re-signed, remove payload/signature headers which might be already present
	m.Metadata.Delete(PayloadHeaderKey)
	m.Metadata.Delete(SignatureHeaderKey)

	payload := BuildGRPCPayload(m.Metadata, m.Method)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	signature, err := signer.Sign(payloadJSON)
	if err != nil {
		return err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	m.Metadata.Set(PayloadHeaderKey, string(payloadJSON))
	m.Metadata.Set(SignatureHeaderKey, fmt.Sprintf("%s %s %s %s", SignatureVersionV1, identity, signer.Fingerprint(), signatureBase64))

	return nil
}

// VerifyJWT verifies the JWT token on the message and returns the verified claims.
func (m *GRPC) VerifyJWT(ctx context.Context, verifier jwt.Verifier) (*jwt.Claims, error) {
	messageJWT, err := m.JWT()
	if err != nil {
		return nil, err
	}

	return verifier.Verify(ctx, messageJWT)
}

// VerifySignature verifies the signature of the message.
// It includes the verifications for the timestamp and the payload.
func (m *GRPC) VerifySignature(verifier SignatureVerifier) error {
	timestamp, err := m.timestamp()
	if err != nil {
		return err
	}

	err = verifyTimestamp(timestamp)
	if err != nil {
		return err
	}

	payload, err := m.payload()
	if err != nil {
		return err
	}

	err = m.verifyPayload(payload)
	if err != nil {
		return err
	}

	payloadJSON, err := payload.JSON()
	if err != nil {
		return err
	}

	signature, err := m.Signature()
	if err != nil {
		return err
	}

	return verifier.Verify(payloadJSON, signature.Signature)
}

func (m *GRPC) verifyPayload(payload *GRPCPayload) error {
	if payload == nil {
		return fmt.Errorf("%w: %s", ErrNotFound, PayloadHeaderKey)
	}

	if payload.Method != m.Method {
		return fmt.Errorf("payload method does not match: %s != %s", payload.Method, m.Method)
	}

	for _, header := range includedHeaders {
		if !reflect.DeepEqual(payload.Headers[header], m.Metadata[header]) {
			return fmt.Errorf("payload header does not match: %s", header)
		}
	}

	return nil
}

func (m *GRPC) firstHeader(name string) string {
	values := m.Metadata.Get(name)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}
