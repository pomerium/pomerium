package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		bare, err := CreateCodeWithRecordVersion(CodeTypeAccess, "session-2", expires, "", srv.cipher, 7)
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
		tok, err := srv.CreateRefreshToken("session-3", "client-a", expires)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(tok, "pom_mrt_"), "got %q", tok)

		code, err := srv.DecryptRefreshToken(tok, "client-a")
		require.NoError(t, err)
		assert.Equal(t, "session-3", code.GetId())
	})

	t.Run("bare", func(t *testing.T) {
		bare, err := CreateCode(CodeTypeRefresh, "session-4", expires, "client-b", srv.cipher)
		require.NoError(t, err)
		require.False(t, strings.HasPrefix(bare, refreshTokenPrefix))

		code, err := srv.DecryptRefreshToken(bare, "client-b")
		require.NoError(t, err)
		assert.Equal(t, "session-4", code.GetId())
	})
}
