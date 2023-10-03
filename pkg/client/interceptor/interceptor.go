// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package interceptor provides a GRPC client interceptor that signs requests.
package interceptor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/pkg/browser"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/siderolabs/go-api-signature/pkg/message"
	"github.com/siderolabs/go-api-signature/pkg/pgp/client"
	"github.com/siderolabs/go-api-signature/pkg/serviceaccount"
)

func init() {
	// suppress xdg-open errors
	browser.Stderr = nil
}

// SkipInterceptorContextKey is a context key used to skip interceptor to avoid infinite recursion.
type SkipInterceptorContextKey struct{}

// AuthEnabledFunc is called once to determine if auth is enabled.
type AuthEnabledFunc func(ctx context.Context, cc *grpc.ClientConn) (bool, error)

// UserKeyFunc is a function that is called to read the initial user (non-service-account) key.
type UserKeyFunc func(ctx context.Context, cc *grpc.ClientConn, options *Options) (message.Signer, error)

// Options are the options for the interceptor.
type Options struct {
	InfoWriter       io.Writer
	AuthEnabledFunc  AuthEnabledFunc
	GetUserKeyFunc   UserKeyFunc
	RenewUserKeyFunc UserKeyFunc

	UserKeyProvider *client.KeyProvider

	ContextName string
	Identity    string
	ClientName  string

	// ServiceAccountBase64 is a static service account key in base64 format.
	// When specified, ContextName and Identity are ignored and retries are never attempted.
	ServiceAccountBase64 string
}

// Interceptor is a GRPC interceptor that provides Unary and Stream client interceptors.
type Interceptor struct {
	userSigner     message.Signer
	initErr        error
	serviceAccount *serviceaccount.ServiceAccount
	options        Options
	initOnce       sync.Once
	userSignerLock sync.Mutex
	authEnabled    bool
}

// New creates a new client interceptor.
func New(options Options) *Interceptor {
	if options.InfoWriter == nil {
		options.InfoWriter = os.Stderr
	}

	if options.AuthEnabledFunc == nil {
		options.AuthEnabledFunc = func(ctx context.Context, cc *grpc.ClientConn) (bool, error) {
			return true, nil
		}
	}

	if options.GetUserKeyFunc == nil {
		options.GetUserKeyFunc = func(ctx context.Context, cc *grpc.ClientConn, options *Options) (message.Signer, error) {
			return options.UserKeyProvider.ReadValidKey(options.ContextName, options.Identity)
		}
	}

	if options.RenewUserKeyFunc == nil {
		options.RenewUserKeyFunc = renewUserKeyViaAuthFlow
	}

	return &Interceptor{
		options: options,
	}
}

// Unary returns a new unary client interceptor which signs requests.
func (i *Interceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return i.intercept(ctx, cc, method, func(ctx context.Context) error {
			return invoker(ctx, method, req, reply, cc, opts...)
		})
	}
}

// Stream returns a new streaming client interceptor which signs requests.
func (i *Interceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		var stream grpc.ClientStream

		err := i.intercept(ctx, cc, method, func(ctx context.Context) error {
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

func (i *Interceptor) intercept(ctx context.Context, cc *grpc.ClientConn, method string, fn func(context.Context) error) error {
	if ctx.Value(SkipInterceptorContextKey{}) != nil {
		return fn(ctx)
	}

	ctx = context.WithValue(ctx, SkipInterceptorContextKey{}, struct{}{})

	if err := i.initializeOnce(ctx, cc); err != nil {
		return err
	}

	if !i.authEnabled {
		return fn(ctx)
	}

	unsignedCtx := ctx
	isRetryable := i.serviceAccount == nil

	signAndMakeCall := func() (bool, error) {
		signedCtx, err := i.sign(unsignedCtx, cc, method)
		if err != nil {
			return isRetryable, err
		}

		err = fn(signedCtx)
		if err != nil {
			return status.Code(err) == codes.Unauthenticated && isRetryable, err
		}

		return false, nil
	}

	for {
		retry, err := signAndMakeCall()
		if err == nil { // call succeeded
			return nil
		}

		if !retry { // should not retry
			return err
		}

		fmt.Fprintf(i.options.InfoWriter, "Could not authenticate: %v\n", err)

		if err = i.renewUser(ctx, cc); err != nil {
			return err
		}

		isRetryable = false // mark as not retryable since we already tried once
	}
}

func (i *Interceptor) renewUser(ctx context.Context, cc *grpc.ClientConn) error {
	newSigner, err := i.options.RenewUserKeyFunc(ctx, cc, &i.options)
	if err != nil {
		return err
	}

	i.setUserSigner(newSigner)

	return nil
}

func (i *Interceptor) sign(ctx context.Context, cc *grpc.ClientConn, method string) (context.Context, error) {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	msg := message.NewGRPC(md, method)

	var (
		identity string
		signer   message.Signer
	)

	if i.serviceAccount != nil {
		identity = i.serviceAccount.Name
		signer = i.serviceAccount.Key
	} else {
		identity = i.options.Identity

		var err error

		signer, err = i.initAndGetUserSigner(ctx, cc)
		if err != nil {
			return nil, fmt.Errorf("failed to get signer: %w", err)
		}
	}

	if err := msg.Sign(identity, signer); err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return metadata.NewOutgoingContext(ctx, msg.Metadata), nil
}

func (i *Interceptor) initAndGetUserSigner(ctx context.Context, cc *grpc.ClientConn) (message.Signer, error) {
	i.userSignerLock.Lock()
	defer i.userSignerLock.Unlock()

	if i.userSigner != nil {
		return i.userSigner, nil
	}

	key, err := i.options.GetUserKeyFunc(ctx, cc, &i.options)
	if err != nil {
		return nil, err
	}

	i.userSigner = key

	return i.userSigner, nil
}

func (i *Interceptor) setUserSigner(signer message.Signer) {
	i.userSignerLock.Lock()
	defer i.userSignerLock.Unlock()

	i.userSigner = signer
}

func (i *Interceptor) initializeOnce(ctx context.Context, cc *grpc.ClientConn) error {
	i.initOnce.Do(func() {
		i.initErr = i.initialize(ctx, cc)
	})

	return i.initErr
}

func (i *Interceptor) initialize(ctx context.Context, cc *grpc.ClientConn) error {
	authEnabled, err := i.options.AuthEnabledFunc(ctx, cc)
	if err != nil {
		return err
	}

	i.authEnabled = authEnabled

	saInitialized, err := i.initServiceAccount()
	if err != nil {
		return err
	}

	if saInitialized {
		return nil
	}

	if _, err = i.initAndGetUserSigner(ctx, cc); err != nil {
		fmt.Fprintf(i.options.InfoWriter, "Could not authenticate: %v\n", err)

		renewedSigner, renewErr := i.options.RenewUserKeyFunc(ctx, cc, &i.options)
		if renewErr != nil {
			return errors.Join(err, renewErr)
		}

		i.setUserSigner(renewedSigner)
	}

	return nil
}

// initServiceAccount initializes the service account.
// It returns true if a service account was initialized.
func (i *Interceptor) initServiceAccount() (bool, error) {
	initServiceAccount := func(val string) error {
		sa, err := serviceaccount.Decode(val)
		if err != nil {
			return err
		}

		i.serviceAccount = sa

		return nil
	}

	// explicit service account in options
	if i.options.ServiceAccountBase64 != "" {
		if err := initServiceAccount(i.options.ServiceAccountBase64); err != nil {
			return false, fmt.Errorf("failed to decode service account key from options: %w", err)
		}

		return true, nil
	}

	envKey, valueBase64 := serviceaccount.GetFromEnv()
	if envKey != "" {
		if err := initServiceAccount(valueBase64); err != nil {
			return false, fmt.Errorf("failed to decode service account key from env var %q: %w", envKey, err)
		}

		return true, nil
	}

	return false, nil
}
