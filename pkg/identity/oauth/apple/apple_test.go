package apple_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oauth/apple"
)

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://appleid.apple.com",
		apple.GetOptions(&oauth.Options{}).ProviderURL,
		"should set default provider url")
	assert.Equal(t,
		[]string{"name", "email"},
		apple.GetOptions(&oauth.Options{}).Scopes,
		"should set default scopes")
}
