package agentic

import (
	"crypto/cipher"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func newTestCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	c, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)
	return c
}

func TestMintParseRunToken_RoundTrip(t *testing.T) {
	c := newTestCipher(t)

	tok, err := MintRunToken(c, "run-123", time.Now().Add(time.Hour), 42)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(tok, RunTokenPrefix), "token must carry the run-token prefix")

	runID, version, err := ParseRunToken(c, tok)
	require.NoError(t, err)
	assert.Equal(t, "run-123", runID)
	assert.Equal(t, uint64(42), version)
}

func TestParseRunToken_WrongCipher(t *testing.T) {
	c1, c2 := newTestCipher(t), newTestCipher(t)

	tok, err := MintRunToken(c1, "run-1", time.Now().Add(time.Hour), 0)
	require.NoError(t, err)

	_, _, err = ParseRunToken(c2, tok)
	assert.Error(t, err, "a token sealed with a different cipher must not decrypt")
}

func TestParseRunToken_Expired(t *testing.T) {
	c := newTestCipher(t)

	// Minting with a past expiry is allowed (non-zero); parsing must reject it.
	tok, err := MintRunToken(c, "run-1", time.Now().Add(-time.Minute), 0)
	require.NoError(t, err)

	_, _, err = ParseRunToken(c, tok)
	assert.Error(t, err, "an expired run token must be rejected")
}

func TestRunTokenFromAuthorizationHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"valid", "Bearer pom_art_abc", "pom_art_abc", true},
		{"case-insensitive bearer", "bearer pom_art_abc", "pom_art_abc", true},
		{"not a run token", "Bearer eyJhbGciOiJ", "", false},
		{"missing bearer prefix", "pom_art_abc", "", false},
		{"empty", "", "", false},
		{"bearer only", "Bearer ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := RunTokenFromAuthorizationHeader(tc.in)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
