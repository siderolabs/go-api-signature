// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package interceptor_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/siderolabs/go-api-signature/pkg/client/interceptor"
	"github.com/siderolabs/go-api-signature/pkg/message"
)

type testSigner struct {
	id string
}

func (t *testSigner) Fingerprint() string {
	return t.id
}

func (t *testSigner) Sign(data []byte) ([]byte, error) {
	return []byte(t.id + " " + string(data)), nil
}

type testServer struct {
	grpc_testing.UnimplementedTestServiceServer
	t *testing.T
}

// UnaryCall accepts the signatures signed by signer-2. If the message is signed by signer-1,
// it will only accept it if it has "accept-signature-1" in its payload.
// This way we are able to test the signer fallback mechanism, where when a signature is invalid, the client will
// attempt to reauthenticate, renew its signature and retry the request.
func (s testServer) UnaryCall(ctx context.Context, req *grpc_testing.SimpleRequest) (*grpc_testing.SimpleResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	assert.True(s.t, ok)

	sigs := md.Get(message.SignatureHeaderKey)
	assert.Len(s.t, sigs, 1)

	sig := sigs[0]

	if string(req.GetPayload().GetBody()) == "accept-signature-1" {
		return &grpc_testing.SimpleResponse{
			Payload: &grpc_testing.Payload{
				Body: []byte("valid-signature-1"),
			},
		}, nil
	}

	if strings.HasPrefix(sig, fmt.Sprintf("%s test@example.org signer-2", message.SignatureVersionV1)) {
		return &grpc_testing.SimpleResponse{
			Payload: &grpc_testing.Payload{
				Body: []byte("valid-signature-2"),
			},
		}, nil
	}

	return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("signature is not valid: %s", sig))
}

func (s testServer) StreamingOutputCall(_ *grpc_testing.StreamingOutputCallRequest, stream grpc_testing.TestService_StreamingOutputCallServer) error {
	ctx := stream.Context()

	md, ok := metadata.FromIncomingContext(ctx)
	assert.True(s.t, ok)

	sigs := md.Get(message.SignatureHeaderKey)
	assert.Len(s.t, sigs, 1)

	if strings.HasPrefix(sigs[0], fmt.Sprintf("%s test@example.org signer-1", message.SignatureVersionV1)) {
		return stream.Send(&grpc_testing.StreamingOutputCallResponse{
			Payload: &grpc_testing.Payload{
				Body: []byte("valid-signature-1"),
			},
		})
	}

	return nil
}

type SignatureTestSuite struct {
	testServiceClient grpc_testing.TestServiceClient

	clientConn *grpc.ClientConn

	GRPCSuite
}

func (suite *SignatureTestSuite) SetupSuite() {
	suite.InitServer()

	grpc_testing.RegisterTestServiceServer(suite.Server, testServer{
		t: suite.T(),
	})

	suite.StartServer()

	testSigner1 := &testSigner{
		id: "signer-1",
	}

	testSigner2 := &testSigner{
		id: "signer-2",
	}

	var err error

	clientInterceptor := interceptor.New(interceptor.Options{
		GetUserKeyFunc: func(_ context.Context, _ *grpc.ClientConn, _ *interceptor.Options) (message.Signer, error) {
			return testSigner1, nil
		},
		RenewUserKeyFunc: func(_ context.Context, _ *grpc.ClientConn, _ *interceptor.Options) (message.Signer, error) {
			return testSigner2, nil
		},
		Identity: "test@example.org",
	})

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(clientInterceptor.Unary()),
		grpc.WithStreamInterceptor(clientInterceptor.Stream()),
	}

	suite.clientConn, err = grpc.NewClient(suite.Target, dialOptions...)
	suite.Require().NoError(err)

	suite.testServiceClient = grpc_testing.NewTestServiceClient(suite.clientConn)
}

func (suite *SignatureTestSuite) TearDownSuite() {
	suite.clientConn.Close() //nolint:errcheck
	suite.StopServer()
}

// TestUnaryFirstAttempt tests a valid signature on the first attempt.
func (suite *SignatureTestSuite) TestUnaryFirstAttempt() {
	response, err := suite.testServiceClient.UnaryCall(context.Background(), &grpc_testing.SimpleRequest{
		Payload: &grpc_testing.Payload{
			Body: []byte("accept-signature-1"),
		},
	})

	suite.Assert().NoError(err)

	suite.Assert().Equal("valid-signature-1", string(response.Payload.Body))
}

// TestUnarySecondAttempt tests an invalid signature and the renewal mechanism.
func (suite *SignatureTestSuite) TestUnarySecondAttempt() {
	response, err := suite.testServiceClient.UnaryCall(context.Background(), &grpc_testing.SimpleRequest{})
	suite.Assert().NoError(err)

	suite.Assert().Equal("valid-signature-2", string(response.Payload.Body))
}

func (suite *SignatureTestSuite) TestStreamFirstAttempt() {
	stream, err := suite.testServiceClient.StreamingOutputCall(context.Background(), &grpc_testing.StreamingOutputCallRequest{})
	suite.Assert().NoError(err)

	response, err := stream.Recv()
	suite.Assert().NoError(err)

	suite.Assert().Equal("valid-signature-1", string(response.Payload.Body))
}

func TestSignatureTestSuite(t *testing.T) {
	suite.Run(t, new(SignatureTestSuite))
}
