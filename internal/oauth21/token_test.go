package oauth21_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/oauth21"
)

func TestParseTokenRequest_BasicAuth(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "abc")
	req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("myclient", "secret")

	tr, err := oauth21.ParseTokenRequest(req)
	require.NoError(t, err)
	require.NotNil(t, tr.ClientId)
	require.Equal(t, "myclient", *tr.ClientId)
	require.NotNil(t, tr.ClientSecret)
	require.Equal(t, "secret", *tr.ClientSecret)
}

func TestParseTokenRequest_BasicAuthWithBodyOverride(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "abc")
	form.Set("client_id", "bodyid")
	form.Set("client_secret", "bodysecret")
	req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basicid", "basicsecret")

	tr, err := oauth21.ParseTokenRequest(req)
	require.NoError(t, err)
	require.NotNil(t, tr.ClientId)
	require.Equal(t, "bodyid", *tr.ClientId) // body should win
	require.NotNil(t, tr.ClientSecret)
	require.Equal(t, "bodysecret", *tr.ClientSecret)
}
