package oauth21_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	clientBasic := rfc7591v1.TokenEndpointAuthMethodClientSecretBasic
	clientNone := rfc7591v1.TokenEndpointAuthMethodNone
	for _, tc := range []struct {
		name   string
		client *rfc7591v1.Metadata
		req    *gen.AuthorizationRequest
		err    bool
	}{
		{
			"default token auth method, no code challenge",
			&rfc7591v1.Metadata{
				RedirectUris: []string{"https://example.com/callback", "https://example.com/other-callback"},
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("https://example.com/callback"),
			},
			true,
		},
		{
			"none token auth method, no code challenge",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/other-callback"},
				TokenEndpointAuthMethod: &clientNone,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("https://example.com/callback"),
			},
			true,
		},
		{
			"none token auth method, code challenge is provided",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/other-callback"},
				TokenEndpointAuthMethod: &clientNone,
			},
			&gen.AuthorizationRequest{
				RedirectUri:   new("https://example.com/callback"),
				CodeChallenge: new("challenge"),
			},
			false,
		},
		{
			"none token auth method, code challenge and method are provided",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/other-callback"},
				TokenEndpointAuthMethod: &clientNone,
			},
			&gen.AuthorizationRequest{
				RedirectUri:         new("https://example.com/callback"),
				CodeChallenge:       new("challenge"),
				CodeChallengeMethod: new("S256"),
			},
			false,
		},
		{
			"optional redirect_uri, multiple redirect_uris",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/other-callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: nil,
			},
			true,
		},
		{
			"optional redirect_uri, single redirect_uri",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: nil,
			},
			false,
		},
		{
			"matching redirect_uri",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/other-callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("https://example.com/callback"),
			},
			false,
		},
		{
			"non-matching redirect_uri",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/other-callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("https://example.com/invalid-callback"),
			},
			true,
		},
		{
			"loopback localhost: port in request, no port registered",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"http://localhost/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("http://localhost:59709/callback"),
			},
			false,
		},
		{
			"loopback 127.0.0.1: port in request, no port registered",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"http://127.0.0.1/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("http://127.0.0.1:12345/callback"),
			},
			false,
		},
		{
			"loopback localhost: different ports both specified",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"http://localhost:3000/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("http://localhost:59709/callback"),
			},
			false,
		},
		{
			"loopback localhost: exact match with port",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"http://localhost:3000/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("http://localhost:3000/callback"),
			},
			false,
		},
		{
			"loopback localhost: different path still rejected",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"http://localhost/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("http://localhost:59709/evil"),
			},
			true,
		},
		{
			"loopback localhost: different scheme still rejected",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"http://localhost/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("https://localhost:59709/callback"),
			},
			true,
		},
		{
			"non-loopback: port mismatch still rejected",
			&rfc7591v1.Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: &clientBasic,
			},
			&gen.AuthorizationRequest{
				RedirectUri: new("https://example.com:8443/callback"),
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
