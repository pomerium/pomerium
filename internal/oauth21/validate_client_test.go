package oauth21_test

import (
	"testing"

	"github.com/zeebo/assert"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		client *rfc7591v1.ClientMetadata
		req    *gen.AuthorizationRequest
		err    bool
	}{
		{
			"optional redirect_uri, multiple redirect_uris",
			&rfc7591v1.ClientMetadata{
				RedirectUris: []string{"https://example.com/callback", "https://example.com/other-callback"},
			},
			&gen.AuthorizationRequest{
				RedirectUri: nil,
			},
			true,
		},
		{
			"optional redirect_uri, single redirect_uri",
			&rfc7591v1.ClientMetadata{
				RedirectUris: []string{"https://example.com/callback"},
			},
			&gen.AuthorizationRequest{
				RedirectUri: nil,
			},
			false,
		},
		{
			"matching redirect_uri",
			&rfc7591v1.ClientMetadata{
				RedirectUris: []string{"https://example.com/callback", "https://example.com/other-callback"},
			},
			&gen.AuthorizationRequest{
				RedirectUri: proto.String("https://example.com/callback"),
			},
			false,
		},
		{
			"non-matching redirect_uri",
			&rfc7591v1.ClientMetadata{
				RedirectUris: []string{"https://example.com/callback", "https://example.com/other-callback"},
			},
			&gen.AuthorizationRequest{
				RedirectUri: proto.String("https://example.com/invalid-callback"),
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
