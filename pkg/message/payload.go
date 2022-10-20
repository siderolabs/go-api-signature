// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package message

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/metadata"
)

var includedHeaders = []string{
	TimestampHeaderKey,
	NodesHeaderKey,
	SelectorsHeaderKey,
	FieldSelectorsHeaderKey,
	RuntimeHeaderHey,
	ContextHeaderKey,
	ClusterHeaderKey,
	NamespaceHeaderKey,
	UIDHeaderKey,
	AuthorizationHeaderKey,
}

// GRPCPayload represents the payload to be signed.
//
// Its JSON representation is added to the GRPC metadata.
// On signature verification, the signature is verified against the JSON representation of the payload.
// The payload itself is verified against the actual GRPC message.
type GRPCPayload struct {
	Headers map[string][]string `json:"headers,omitempty"`
	Method  string              `json:"method"`

	originalJSON []byte
}

// ParseGRPCPayload parses the header value.
//
// This method is used in the verification flow.
func ParseGRPCPayload(payloadJSON []byte) (*GRPCPayload, error) {
	p := GRPCPayload{
		originalJSON: payloadJSON,
	}

	err := json.Unmarshal(payloadJSON, &p)

	return &p, err
}

// BuildGRPCPayload builds the payload based on the request metadata.
//
// This method is used in the signing flow.
func BuildGRPCPayload(md metadata.MD, method string) *GRPCPayload {
	headers := make(map[string][]string)

	for _, header := range includedHeaders {
		headers[header] = md.Get(header)
	}

	return &GRPCPayload{
		Headers: headers,
		Method:  method,
	}
}

// JSON returns the original JSON representation of the payload.
//
// This method is only valid after ParseGRPCPayload.
func (p *GRPCPayload) JSON() ([]byte, error) {
	if p.originalJSON == nil {
		return nil, fmt.Errorf("no JSON was captured")
	}

	return p.originalJSON, nil
}
