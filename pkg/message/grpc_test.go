// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message_test

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/siderolabs/go-api-signature/pkg/message"
)

func TestGRPC(t *testing.T) {
	m := message.GRPC{
		Metadata: metadata.Pairs(
			"cluster", "foo",
			"node", "bar",
		),
		Method: "some.method.Name",
	}

	const identity = "test@example.com"

	require.NoError(t, m.Sign(identity, mockSignerVerifier{}))

	assert.NotEmpty(t, m.Metadata.Get(message.PayloadHeaderKey))
	assert.NotEmpty(t, m.Metadata.Get(message.SignatureHeaderKey))
	assert.NotEmpty(t, m.Metadata.Get(message.TimestampHeaderKey))

	signature, err := m.Signature()
	require.NoError(t, err)

	assert.Equal(t, identity, signature.Identity)

	assert.NoError(t, m.VerifySignature(mockSignerVerifier{}))

	for _, tt := range []struct {
		mutator       func(*testing.T, metadata.MD)
		name          string
		expectFailure bool
	}{
		{
			name:          "no changes",
			mutator:       func(t *testing.T, md metadata.MD) {},
			expectFailure: false,
		},
		{
			name: "important header",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Set("cluster", "baz")
			},
			expectFailure: true,
		},
		{
			name: "not important header",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Set("foo", "bar")
			},
			expectFailure: false,
		},
		{
			name: "corrupt signature",
			mutator: func(t *testing.T, md metadata.MD) {
				signature := md.Get(message.SignatureHeaderKey)[0]
				md.Set(message.SignatureHeaderKey, signature+"0")
			},
			expectFailure: true,
		},
		{
			name: "mutate signed payload",
			mutator: func(t *testing.T, md metadata.MD) {
				payload := md.Get(message.PayloadHeaderKey)[0]

				p, err := message.ParseGRPCPayload([]byte(payload))
				require.NoError(t, err)

				p.Method = "some.other.method.Name"

				marshaled, err := json.Marshal(p)
				require.NoError(t, err)

				md.Set(message.PayloadHeaderKey, string(marshaled))
			},
			expectFailure: true,
		},
		{
			name: "mutate timestamp --",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Set(message.TimestampHeaderKey, strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
			},
			expectFailure: true,
		},
		{
			name: "mutate timestamp ++",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Set(message.TimestampHeaderKey, strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
			},
			expectFailure: true,
		},
		{
			name: "drop signature",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Delete(message.SignatureHeaderKey)
			},
			expectFailure: true,
		},
		{
			name: "drop payload",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Delete(message.PayloadHeaderKey)
			},
			expectFailure: true,
		},
		{
			name: "drop timestamp",
			mutator: func(t *testing.T, md metadata.MD) {
				md.Delete(message.TimestampHeaderKey)
			},
			expectFailure: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mCopy := m
			mCopy.Metadata = mCopy.Metadata.Copy()

			tt.mutator(t, mCopy.Metadata)
			if tt.expectFailure {
				assert.Error(t, mCopy.VerifySignature(mockSignerVerifier{}))
			} else {
				assert.NoError(t, mCopy.VerifySignature(mockSignerVerifier{}))
			}
		})
	}
}
