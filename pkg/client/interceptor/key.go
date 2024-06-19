// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package interceptor

import (
	"context"
	"fmt"
	"os"

	"github.com/pkg/browser"
	"google.golang.org/grpc"

	"github.com/siderolabs/go-api-signature/pkg/client/auth"
	"github.com/siderolabs/go-api-signature/pkg/message"
)

func renewUserKeyViaAuthFlow(ctx context.Context, cc *grpc.ClientConn, options *Options) (message.Signer, error) {
	ctx = context.WithValue(ctx, SkipInterceptorContextKey{}, struct{}{})

	authCli := auth.NewClient(cc)

	err := options.UserKeyProvider.DeleteKey(options.ContextName, options.Identity)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	pgpKey, err := options.UserKeyProvider.GenerateKey(options.ContextName, options.Identity, options.ClientName)
	if err != nil {
		return nil, err
	}

	publicKey, err := pgpKey.ArmorPublic()
	if err != nil {
		return nil, err
	}

	loginURL, err := authCli.RegisterPGPPublicKey(ctx, options.Identity, []byte(publicKey))
	if err != nil {
		return nil, err
	}

	savePath, err := options.UserKeyProvider.WriteKey(pgpKey)
	if err != nil {
		return nil, err
	}

	printLoginDialog := func() {
		fmt.Fprintf(os.Stderr, "Please visit this page to authenticate: %s\n", loginURL)
	}

	browserEnv := os.Getenv("BROWSER")
	if browserEnv == "echo" {
		printLoginDialog()
	} else {
		fmt.Fprintf(os.Stderr, "Attempting to open URL: %s\n", loginURL)

		err = browser.OpenURL(loginURL)
		if err != nil {
			printLoginDialog()
		}
	}

	publicKeyID := pgpKey.Key.Fingerprint()

	err = authCli.AwaitPublicKeyConfirmation(ctx, publicKeyID)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck
	fmt.Fprintf(options.InfoWriter, "Public key %s is now registered for user %s\n", publicKeyID, options.Identity)
	fmt.Fprintf(options.InfoWriter, "PGP key saved to %s\n", savePath) //nolint:errcheck

	return pgpKey, nil
}
