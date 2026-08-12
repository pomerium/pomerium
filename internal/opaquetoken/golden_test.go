package opaquetoken

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// goldenKey is a fixed sealing key. It exists only so the golden tokens below
// can be opened; it is not a secret and must not be used anywhere else.
const goldenKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

// TestOpenGolden opens tokens that were minted before this codec moved out of
// internal/mcp, when the payload was oauth21.Code and its type field was named
// grant_type. Proto3 binary encoding carries field numbers, not message, field
// or package names, so renaming those is transparent on the wire — but only as
// long as the numbers do not move. These pinned ciphertexts are what proves it:
// tokens issued by earlier builds are still presented to newer ones, and must
// keep opening.
//
// If this test fails, the wire format changed and previously issued tokens are
// being rejected. Do not regenerate the golden values.
func TestOpenGolden(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString(goldenKey)
	require.NoError(t, err)
	cipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	// The expiration that was sealed into both tokens.
	expiresAt := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	now := expiresAt.Add(-time.Hour)

	for _, tc := range []struct {
		name              string
		token             string
		typ               Type
		ad                string
		wantID            string
		wantRecordVersion uint64
	}{
		{
			name:              "access token with record version",
			token:             "85qVBSiFllkZmrF91D2Kb6ui6malLxT0HKhTKjKxFldht0LHZS6NYYuzS5tC9RDTyr4Tgpmqsiiaaxu1cx1p/92oiRsWsKw=",
			typ:               TypeAccess,
			ad:                "",
			wantID:            "golden-session-id",
			wantRecordVersion: 42,
		},
		{
			name:   "authorization code bound to a client id",
			token:  "FK9mlhvmpNdBrGEhqqYteW3IP+RB/LqKHWvcPyknVerYeTn3N4wGMfquEHFG53JkiWToahfx700ej8dtUsKUU02sVWucQA==",
			typ:    TypeAuthorization,
			ad:     "golden-client-id",
			wantID: "golden-auth-req-id",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := Open(tc.typ, tc.token, cipher, tc.ad, now)
			require.NoError(t, err)
			assert.Equal(t, tc.wantID, payload.GetId())
			assert.Equal(t, tc.typ, payload.GetType())
			assert.Equal(t, tc.wantRecordVersion, payload.GetRecordVersion())
			assert.Equal(t, expiresAt, payload.GetExpiresAt().AsTime().UTC())
		})
	}
}
