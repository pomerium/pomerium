package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRefresh(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(clearTimeout)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "NEW_TOKEN",
			"refresh_token": "NEW_REFRESH_TOKEN",
			"expires_in": 3600
		}`))
	}))
	t.Cleanup(s.Close)

	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: s.URL}}

	token := &oauth2.Token{
		AccessToken:  "OLD_TOKEN",
		RefreshToken: "OLD_REFRESH_TOKEN",

		// Even if a token is not expiring soon, Refresh() should still perform
		// the refresh.
		Expiry: time.Now().Add(time.Hour),
	}
	require.True(t, token.Valid())

	newToken, err := Refresh(ctx, cfg, token)
	require.NoError(t, err)
	assert.Equal(t, "NEW_TOKEN", newToken.AccessToken)
	assert.Equal(t, "NEW_REFRESH_TOKEN", newToken.RefreshToken)
}

func TestRefresh_errors(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(clearTimeout)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("{}"))
	}))
	t.Cleanup(s.Close)

	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: s.URL}}

	_, err := Refresh(ctx, cfg, nil)
	assert.Equal(t, ErrMissingRefreshToken, err)

	_, err = Refresh(ctx, cfg, &oauth2.Token{})
	assert.Equal(t, ErrMissingRefreshToken, err)

	_, err = Refresh(ctx, cfg, &oauth2.Token{RefreshToken: "REFRESH_TOKEN"})
	assert.Equal(t, "identity/oidc: refresh failed: oauth2: server response missing access_token",
		err.Error())
}
