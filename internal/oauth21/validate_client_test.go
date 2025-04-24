package oauth21_test

import (
	"testing"

	"github.com/zeebo/assert"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func ValidateClientTest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		client *rfc7591v1.ClientRegistrationRequest
		req    *gen.AuthorizationRequest
		err    bool
	}{
		{
			"optional redirect_uri, multiple redirect_uris",
			&rfc7591v1.ClientRegistrationRequest{
				RedirectUris: []string{"https://example.com/callback", "https://example.com/other-callback"},
			},
			&gen.AuthorizationRequest{
				RedirectUri: nil,
			},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := oauth21.ValidateAuthorizationRequest(tc.client, tc.req)
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
