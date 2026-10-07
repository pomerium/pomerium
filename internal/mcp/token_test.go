package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/opaquetoken"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func newTokenTestHandler(t *testing.T) *Handler {
	t.Helper()
	testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)
	return &Handler{cipher: testCipher}
}

func TestAccessTokenPrefix(t *testing.T) {
	srv := newTokenTestHandler(t)
	expires := time.Now().Add(time.Hour)

	t.Run("prefixed", func(t *testing.T) {
		tok, err := srv.GetAccessTokenForSessionWithVersion("session-1", 42, expires)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(tok, "pom_mat_"), "got %q", tok)

		id, version, err := srv.GetSessionAndVersionFromAccessToken(tok)
		require.NoError(t, err)
		assert.Equal(t, "session-1", id)
		assert.Equal(t, uint64(42), version)
	})

	t.Run("bare", func(t *testing.T) {
		bare, err := opaquetoken.Seal(opaquetoken.TypeAccess, "session-2", expires, "", srv.cipher, opaquetoken.WithRecordVersion(7))
		require.NoError(t, err)
		require.False(t, strings.HasPrefix(bare, accessTokenPrefix))

		id, version, err := srv.GetSessionAndVersionFromAccessToken(bare)
		require.NoError(t, err)
		assert.Equal(t, "session-2", id)
		assert.Equal(t, uint64(7), version)
	})
}

func TestRefreshTokenPrefix(t *testing.T) {
	srv := newTokenTestHandler(t)
	expires := time.Now().Add(time.Hour)

	t.Run("prefixed", func(t *testing.T) {
		issuedAt := time.Now()
		tok, err := srv.CreateRefreshToken("session-3", "client-a", expires, issuedAt)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(tok, "pom_mrt_"), "got %q", tok)

		code, err := srv.DecryptRefreshToken(tok, "client-a")
		require.NoError(t, err)
		assert.Equal(t, "session-3", code.GetId())
		assert.True(t, code.GetIssuedAt().AsTime().Equal(issuedAt))
	})

	t.Run("bare", func(t *testing.T) {
		bare, err := opaquetoken.Seal(opaquetoken.TypeRefresh, "session-4", expires, "client-b", srv.cipher)
		require.NoError(t, err)
		require.False(t, strings.HasPrefix(bare, refreshTokenPrefix))

		code, err := srv.DecryptRefreshToken(bare, "client-b")
		require.NoError(t, err)
		assert.Equal(t, "session-4", code.GetId())
	})
}

// TestRefreshTokenIssuedAtRoundTrips verifies that CreateRefreshToken's issuedAt argument
// round-trips exactly through DecryptRefreshToken: the token endpoint compares this value
// against the session's current issued_at (byte-for-byte via proto equality upstream, and
// here via time equality) to detect a rotated-away refresh token, so any lossiness here
// would make every refresh look like a replay.
func TestRefreshTokenIssuedAtRoundTrips(t *testing.T) {
	srv := newTokenTestHandler(t)
	expires := time.Now().Add(time.Hour)
	issuedAt := time.Now().Add(-30 * time.Minute)

	tok, err := srv.CreateRefreshToken("session-5", "client-c", expires, issuedAt)
	require.NoError(t, err)

	payload, err := srv.DecryptRefreshToken(tok, "client-c")
	require.NoError(t, err)
	require.NotNil(t, payload.GetIssuedAt())
	assert.True(t, payload.GetIssuedAt().AsTime().Equal(issuedAt), "issued_at must round-trip exactly")
}

// TestAccessTokenHasNoIssuedAt verifies that access tokens (unlike refresh tokens) carry
// no issued_at: only refresh tokens need it, to detect rotation.
func TestAccessTokenHasNoIssuedAt(t *testing.T) {
	srv := newTokenTestHandler(t)
	expires := time.Now().Add(time.Hour)

	tok, err := srv.GetAccessTokenForSessionWithVersion("session-6", 1, expires)
	require.NoError(t, err)

	payload, err := opaquetoken.Open(opaquetoken.TypeAccess, strings.TrimPrefix(tok, accessTokenPrefix), srv.cipher, "", time.Now())
	require.NoError(t, err)
	assert.Nil(t, payload.GetIssuedAt())
}
