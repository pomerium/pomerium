package urlutil

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactedNilAndNoUserInfo(t *testing.T) {
	assert.Empty(t, Redacted(nil))

	u, err := url.Parse("https://upstream.example.com/path?q=1")
	require.NoError(t, err)
	assert.Equal(t, "https://upstream.example.com/path?q=1", Redacted(u))
}

func TestRedactedRemovesAllUserInfo(t *testing.T) {
	for _, raw := range []string{
		"https://username-canary:password-canary@upstream.example.com/path",
		"https://token-canary@upstream.example.com/path",
	} {
		t.Run(raw, func(t *testing.T) {
			u, err := url.Parse(raw)
			require.NoError(t, err)
			got := Redacted(u)
			assert.NotContains(t, got, "username-canary")
			assert.NotContains(t, got, "password-canary")
			assert.NotContains(t, got, "token-canary")
			assert.Contains(t, got, "xxxxx@upstream.example.com/path")
		})
	}
}
