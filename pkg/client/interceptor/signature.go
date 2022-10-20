// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package interceptor

import (
	"context"
	"sync"

	"github.com/hashicorp/go-multierror"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/siderolabs/go-api-signature/pkg/message"
)

// SkipInterceptorContextKey is a context key used to skip interceptor to avoid infinite recursion.
type SkipInterceptorContextKey struct{}

// SignerFunc is a function which is called to get a signer.
type SignerFunc func(ctx context.Context, cc *grpc.ClientConn) (message.Signer, error)

// AuthEnabledFunc is called once to determine if auth is enabled.
type AuthEnabledFunc func(ctx context.Context, cc *grpc.ClientConn) (bool, error)

// Signature is a gRPC client interceptor which signs requests.
type Signature struct {
	signer          message.Signer
	signerFunc      SignerFunc
	initErr         error
	renewSignerFunc SignerFunc
	authEnabledFunc AuthEnabledFunc
	identity        string
	initOnce        sync.Once
	authEnabled     bool
}

// NewSignature returns a new Signature interceptor.
//
// renewSignerFunc is a function which is called when the initial Signer is invalid (e.g. got a response with codes.Unauthenticated).
//
// authEnabledFunc is called only once, on the first request to determine if auth is enabled.
// If the result is false, the interceptor will simply pass the following requests through.
func NewSignature(identity string, signerFunc SignerFunc, renewSignerFunc SignerFunc, authEnabledFunc AuthEnabledFunc) *Signature {
	return &Signature{
		identity:        identity,
		signerFunc:      signerFunc,
		renewSignerFunc: renewSignerFunc,
		authEnabledFunc: authEnabledFunc,
	}
}

// Unary returns a new unary client interceptor which signs requests.
func (c *Signature) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return c.intercept(ctx, cc, method, func(ctx context.Context) error {
			return invoker(ctx, method, req, reply, cc, opts...)
		})
	}
}

// Stream returns a new streaming client interceptor which signs requests.
func (c *Signature) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		var stream grpc.ClientStream

		err := c.intercept(ctx, cc, method, func(ctx context.Context) error {
			var streamErr error

			stream, streamErr = streamer(ctx, desc, cc, method, opts...)

			return streamErr
		})
		if err != nil {
			return nil, err
		}

		return stream, nil
	}
}

func (c *Signature) intercept(ctx context.Context, cc *grpc.ClientConn, method string, fn func(context.Context) error) error {
	if ctx.Value(SkipInterceptorContextKey{}) != nil {
		return fn(ctx)
	}

	ctx = context.WithValue(ctx, SkipInterceptorContextKey{}, struct{}{})

	c.initializeOnce(ctx, cc)

	if c.initErr != nil {
		return c.initErr
	}

	if !c.authEnabled {
		return fn(ctx)
	}

	unsignedCtx := ctx

	signedCtx, err := c.sign(unsignedCtx, method)
	if err != nil {
		if c.renewSignerFunc == nil {
			return err
		}

		return c.retry(unsignedCtx, cc, method, fn)
	}

	err = fn(signedCtx)
	if status.Code(err) == codes.Unauthenticated && c.renewSignerFunc != nil {
		return c.retry(unsignedCtx, cc, method, fn)
	}

	return err
}

func (c *Signature) retry(ctx context.Context, cc *grpc.ClientConn, method string, fn func(context.Context) error) error {
	var err error

	c.signer, err = c.renewSignerFunc(ctx, cc)
	if err != nil {
		return err
	}

	ctx, err = c.sign(ctx, method)
	if err != nil {
		return err
	}

	return fn(ctx)
}

func (c *Signature) sign(ctx context.Context, method string) (context.Context, error) {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	msg := message.NewGRPC(md, method)

	err := msg.Sign(c.identity, c.signer)
	if err != nil {
		return nil, err
	}

	return metadata.NewOutgoingContext(ctx, msg.Metadata), nil
}

func (c *Signature) initializeOnce(ctx context.Context, cc *grpc.ClientConn) {
	c.initOnce.Do(func() {
		var err error

		authEnabled, authEnabledErr := c.authEnabledFunc(ctx, cc)
		if authEnabledErr != nil {
			err = multierror.Append(err, authEnabledErr)
		}

		signer, signerErr := c.signerFunc(ctx, cc)
		if signerErr != nil {
			var renewErr error

			signer, renewErr = c.renewSignerFunc(ctx, cc)
			if renewErr != nil {
				err = multierror.Append(err, signerErr, renewErr)
			}
		}

		c.authEnabled = authEnabled
		c.signer = signer
		c.initErr = err
	})
}
