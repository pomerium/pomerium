package rfc7591v1_test

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	rfc7591 "github.com/pomerium/pomerium/internal/rfc7591"
)

func TestValidation(t *testing.T) {
	v := &rfc7591.JsonWebKey{Kty: "Invalid"}
	require.ErrorContains(t, protovalidate.Validate(v), `kty: value must be in list ["RSA", "EC", "oct", "OKP"] [string.in]`)
}

func TestJSONMarshal(t *testing.T) {
	data := `
{
    "redirect_uris": [
        "http://localhost:8002/oauth/callback"
    ],
    "token_endpoint_auth_method": "none",
    "grant_types": [
        "authorization_code",
        "refresh_token"
    ],
    "response_types": [
        "code"
    ],
    "client_name": "MCP Inspector",
    "client_uri": "https://github.com/modelcontextprotocol/inspector"
}`
	v := &rfc7591.ClientMetadata{}
	require.NoError(t, protojson.Unmarshal([]byte(data), v))
	diff := cmp.Diff(&rfc7591.ClientMetadata{
		RedirectUris:            []string{"http://localhost:8002/oauth/callback"},
		TokenEndpointAuthMethod: proto.String("none"),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              proto.String("MCP Inspector"),
		ClientUri:               proto.String("https://github.com/modelcontextprotocol/inspector"),
	}, v, protocmp.Transform())
	require.Empty(t, diff)
}
