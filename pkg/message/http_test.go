// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/message"
)

func TestHTTP(t *testing.T) {
	const body = "hello world"

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPut, "", bytes.NewReader([]byte(body)))
	require.NoError(t, err)

	req.RequestURI = "/some/path"

	m, err := message.NewHTTP(req)
	require.NoError(t, err)

	const identity = "test@example.com"

	require.NoError(t, m.Sign(identity, mockSignerVerifier{}))

	assert.Empty(t, req.Header.Get(message.PayloadHeaderKey))
	assert.NotEmpty(t, req.Header.Get(message.SignatureHeaderKey))
	assert.NotEmpty(t, req.Header.Get(message.TimestampHeaderKey))

	signature, err := m.Signature()
	require.NoError(t, err)

	assert.Equal(t, identity, signature.Identity)

	assert.NoError(t, m.VerifySignature(mockSignerVerifier{}))

	for _, tt := range []struct {
		mutator       func(*testing.T, *http.Request)
		name          string
		expectFailure bool
	}{
		{
			name:          "no changes",
			mutator:       func(*testing.T, *http.Request) {},
			expectFailure: false,
		},
		{
			name: "method",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Method = http.MethodGet
			},
			expectFailure: true,
		},
		{
			name: "not important header",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Header.Set("foo", "bar") //nolint:canonicalheader
			},
			expectFailure: false,
		},
		{
			name: "corrupt signature",
			mutator: func(_ *testing.T, req *http.Request) {
				signature := req.Header.Get(message.SignatureHeaderKey)
				req.Header.Set(message.SignatureHeaderKey, signature+"0")
			},
			expectFailure: true,
		},
		{
			name: "mutate body",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Body = io.NopCloser(bytes.NewReader(nil))
			},
			expectFailure: true,
		},
		{
			name: "mutate uri",
			mutator: func(_ *testing.T, req *http.Request) {
				req.RequestURI = "/other/path"
			},
			expectFailure: true,
		},
		{
			name: "mutate timestamp --",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Header.Set(message.TimestampHeaderKey, strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
			},
			expectFailure: true,
		},
		{
			name: "mutate timestamp ++",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Header.Set(message.TimestampHeaderKey, strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
			},
			expectFailure: true,
		},
		{
			name: "drop signature",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Header.Del(message.SignatureHeaderKey)
			},
			expectFailure: true,
		},
		{
			name: "drop timestamp",
			mutator: func(_ *testing.T, req *http.Request) {
				req.Header.Del(message.TimestampHeaderKey)
			},
			expectFailure: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reqCopy := req.Clone(context.TODO())
			reqCopy.Body = io.NopCloser(bytes.NewReader([]byte(body)))

			tt.mutator(t, reqCopy)

			mCopy, err := message.NewHTTP(reqCopy)
			require.NoError(t, err)

			if tt.expectFailure {
				assert.Error(t, mCopy.VerifySignature(mockSignerVerifier{}))
			} else {
				assert.NoError(t, mCopy.VerifySignature(mockSignerVerifier{}))
			}
		})
	}
}

func TestHTTPMessageSignatures(t *testing.T) {
	t.Parallel()

	t.Run("invalid signature", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		m, err := message.NewHTTP(req)
		require.NoError(t, err)

		_, err = m.Signature()
		require.ErrorIs(t, err, message.ErrInvalidSignature)
	})

	t.Run("no signature", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		m, err := message.NewHTTP(req, message.WithSignatureRequiredCheck(func() (bool, error) {
			return false, nil
		}))
		require.NoError(t, err)

		_, err = m.Signature()
		require.ErrorIs(t, err, message.ErrNotFound)
	})
}
