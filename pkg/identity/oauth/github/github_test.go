package github_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oauth/github"
)

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://github.com",
		github.GetOptions(&oauth.Options{}).ProviderURL,
		"should set default provider url")
	assert.Equal(t,
		[]string{"user:email", "read:org"},
		github.GetOptions(&oauth.Options{}).Scopes,
		"should set default scopes")
}
