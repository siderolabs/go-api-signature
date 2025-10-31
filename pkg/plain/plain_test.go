// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package plain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/go-api-signature/pkg/plain"
)

const signature = "yTEFDFIsNAoTD6TdcoJQtek1giToLxG/eRmcNWBgGp6CRDydj5WPh4Yeq/MSwrqPsWRFESa+3Lfegd1tJ2dN6g=="

const publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8N0YkTeVTfD8xgJsjSMgvAmZquzv
LwfQb9Oa7fBNdyIiS2GPVzSFQtcIYbxBYBzvEY8RZjteEf7e/c/WWznGTQ==
-----END PUBLIC KEY-----`

func TestECDSASignature(t *testing.T) {
	key, err := plain.ParseKey([]byte(publicKey))

	require.NoError(t, err)

	require.NoError(t, key.Verify([]byte("hi there"), []byte(signature)))
}
