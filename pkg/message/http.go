// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DoS Protection.
const maxBodySize = 1024 * 1024

// HTTP represents a gRPC message.
type HTTP struct {
	request *http.Request
	body    []byte
}

// NewHTTP returns a new HTTP message.
func NewHTTP(r *http.Request) (*HTTP, error) {
	var (
		bodyBytes []byte
		err       error
	)

	if r.Body != nil {
		bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err != nil {
			return nil, err
		}

		if err = r.Body.Close(); err != nil {
			return nil, err
		}

		// re-set the body so it can be read in further handlers
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return &HTTP{
		request: r,
		body:    bodyBytes,
	}, nil
}

func (m *HTTP) timestamp() (*time.Time, error) {
	return parseTimestamp(m.request.Header.Get(TimestampHeaderKey)) //nolint:canonicalheader
}

// Signature returns the signature on the message.
func (m *HTTP) Signature() (*Signature, error) {
	return parseSignature(m.request.Header.Get(SignatureHeaderKey)) //nolint:canonicalheader
}

// Sign signs the message with the given signer for SignatureVersionV1.
func (m *HTTP) Sign(identity string, signer Signer) error {
	m.request.Header.Set(TimestampHeaderKey, strconv.FormatInt(time.Now().Unix(), 10)) //nolint:canonicalheader

	payload, err := m.payload()
	if err != nil {
		return err
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	//nolint:canonicalheader
	m.request.Header.Set(SignatureHeaderKey, fmt.Sprintf("%s %s %s %s", SignatureVersionV1, identity, signer.Fingerprint(), signatureBase64))

	return nil
}

// VerifySignature verifies the signature of the message.
// It includes the verifications for the timestamp and the payload.
func (m *HTTP) VerifySignature(verifier SignatureVerifier) error {
	timestamp, err := m.timestamp()
	if err != nil {
		return err
	}

	err = verifyTimestamp(timestamp)
	if err != nil {
		return err
	}

	signature, err := m.Signature()
	if err != nil {
		return err
	}

	payload, err := m.payload()
	if err != nil {
		return err
	}

	return verifier.Verify(payload, signature.Signature)
}

func (m *HTTP) payload() ([]byte, error) {
	timestamp, err := m.timestamp()
	if err != nil {
		return nil, err
	}

	timestampStr := strconv.FormatInt(timestamp.Unix(), 10)

	bodySHA256 := sha256.Sum256(m.body)
	bodySHA256Hex := hex.EncodeToString(bodySHA256[:])

	requestURI := m.request.RequestURI
	if requestURI == "" {
		// client request
		requestURI = m.request.URL.RequestURI()
	}

	payload := strings.Join([]string{m.request.Method, requestURI, timestampStr, bodySHA256Hex}, "\n")

	return []byte(payload), nil
}
