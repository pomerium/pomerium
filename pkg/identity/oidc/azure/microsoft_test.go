package azure_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/azure"
)

func TestAuthCodeOptions(t *testing.T) {
	var options oauth.Options
	p, err := azure.New(context.Background(), &options)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"prompt": "select_account"}, p.AuthCodeOptions)

	options.AuthCodeOptions = map[string]string{}
	p, err = azure.New(context.Background(), &options)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, p.AuthCodeOptions)
}

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://login.microsoftonline.com/common/v2.0",
		azure.GetOptions(&oauth.Options{}).ProviderURL,
		"should set default provider url")
	assert.Equal(t,
		"https://www.example.com",
		azure.GetOptions(&oauth.Options{ProviderURL: "https://www.example.com/"}).ProviderURL,
		"should trim trailing slash")
}
