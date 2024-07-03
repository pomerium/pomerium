package google_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/google"
)

func TestAuthCodeOptions(t *testing.T) {
	t.Parallel()

	var options oauth.Options
	p, err := google.New(context.Background(), &options)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"prompt": "select_account consent", "access_type": "offline"}, p.AuthCodeOptions)

	options.AuthCodeOptions = map[string]string{}
	p, err = google.New(context.Background(), &options)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, p.AuthCodeOptions)
}

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://accounts.google.com",
		google.GetOptions(&oauth.Options{}).ProviderURL,
		"should set default provider url")
	assert.Equal(t,
		[]string{"openid", "profile", "email"},
		google.GetOptions(&oauth.Options{}).Scopes,
		"should set default scopes")
	assert.Equal(t,
		"https://accounts.google.com",
		google.GetOptions(&oauth.Options{ProviderURL: "https://accounts.google.com/"}).ProviderURL,
		"should trim trailing slash")
}
