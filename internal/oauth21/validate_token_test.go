package oauth21_test

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/oauth21/gen"
)

func TestTokenRequestValidation(t *testing.T) {
	validator, err := protovalidate.New()
	require.NoError(t, err)

	testCases := []struct {
		name        string
		request     *gen.TokenRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid authorization_code grant",
			request: &gen.TokenRequest{
				GrantType:    "authorization_code",
				Code:         proto.String("some_code"),
				CodeVerifier: proto.String("code_verifier_should_be_at_least_43_characters_long_123456"),
				ClientId:     proto.String("client_id"),
			},
			expectError: false,
		},
		{
			name: "missing code for authorization_code grant",
			request: &gen.TokenRequest{
				GrantType: "authorization_code",
				ClientId:  proto.String("client_id"),
			},
			expectError: true,
			errorMsg:    "code is required when grant_type is 'authorization_code'",
		},
		{
			name: "code_verifier too short",
			request: &gen.TokenRequest{
				GrantType:    "authorization_code",
				Code:         proto.String("some_code"),
				CodeVerifier: proto.String("too_short"),
				ClientId:     proto.String("client_id"),
			},
			expectError: true,
			errorMsg:    "value length must be at least 43 characters",
		},
		{
			name: "valid refresh_token grant",
			request: &gen.TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: proto.String("refresh_token"),
				Scope:        proto.String("scope1 scope2"),
			},
			expectError: false,
		},
		{
			name: "missing refresh_token for refresh_token grant",
			request: &gen.TokenRequest{
				GrantType: "refresh_token",
			},
			expectError: true,
			errorMsg:    "refresh_token is required when grant_type is 'refresh_token'",
		},
		{
			name: "valid client_credentials grant",
			request: &gen.TokenRequest{
				GrantType: "client_credentials",
				ClientId:  proto.String("client_id"),
				Scope:     proto.String("scope1 scope2"),
			},
			expectError: false,
		},
		{
			name: "invalid grant_type",
			request: &gen.TokenRequest{
				GrantType: "invalid_grant_type",
			},
			expectError: true,
			errorMsg:    "value must be in list",
		},
		{
			name: "empty client_id",
			request: &gen.TokenRequest{
				GrantType: "client_credentials",
				ClientId:  proto.String(""),
			},
			expectError: true,
			errorMsg:    "value length must be at least 1",
		},
		{
			name: "empty scope",
			request: &gen.TokenRequest{
				GrantType: "client_credentials",
				ClientId:  proto.String("client_id"),
				Scope:     proto.String(""),
			},
			expectError: true,
			errorMsg:    "value length must be at least 1",
		},
		{
			name: "empty client_secret",
			request: &gen.TokenRequest{
				GrantType:    "client_credentials",
				ClientId:     proto.String("client_id"),
				ClientSecret: proto.String(""),
			},
			expectError: true,
			errorMsg:    "value length must be at least 1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.request)
			if tc.expectError {
				require.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
