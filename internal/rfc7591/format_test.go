package rfc7591v1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func TestParseMetadata(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Metadata
		wantErr bool
	}{
		{
			name: "minimal valid metadata",
			input: `{
				"redirect_uris": ["https://example.com/callback"]
			}`,
			want: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretBasic),
				GrantTypes:              []string{GrantTypesAuthorizationCode},
				ResponseTypes:           []string{ResponseTypesCode},
			},
			wantErr: false,
		},
		{
			name: "full metadata with all fields",
			input: `{
				"redirect_uris": ["https://example.com/callback", "https://example.com/callback2"],
				"token_endpoint_auth_method": "client_secret_post",
				"grant_types": ["authorization_code", "refresh_token"],
				"response_types": ["code"],
				"client_name": "Test Client",
				"client_name_localized": {"en": "Test Client", "es": "Cliente de Prueba"},
				"client_uri": "https://example.com",
				"client_uri_localized": {"en": "https://example.com/en"},
				"logo_uri": "https://example.com/logo.png",
				"scope": "openid profile email",
				"contacts": ["admin@example.com", "support@example.com"],
				"tos_uri": "https://example.com/tos",
				"policy_uri": "https://example.com/privacy",
				"jwks_uri": "https://example.com/.well-known/jwks.json",
				"software_id": "test-client-v1",
				"software_version": "1.0.0"
			}`,
			want: &Metadata{
				RedirectUris:            []string{"https://example.com/callback", "https://example.com/callback2"},
				TokenEndpointAuthMethod: proto.String("client_secret_post"),
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				ClientName:              proto.String("Test Client"),
				ClientNameLocalized: map[string]string{
					"en": "Test Client",
					"es": "Cliente de Prueba",
				},
				ClientUri: proto.String("https://example.com"),
				ClientUriLocalized: map[string]string{
					"en": "https://example.com/en",
				},
				LogoUri:         proto.String("https://example.com/logo.png"),
				Scope:           proto.String("openid profile email"),
				Contacts:        []string{"admin@example.com", "support@example.com"},
				TosUri:          proto.String("https://example.com/tos"),
				PolicyUri:       proto.String("https://example.com/privacy"),
				JwksUri:         proto.String("https://example.com/.well-known/jwks.json"),
				SoftwareId:      proto.String("test-client-v1"),
				SoftwareVersion: proto.String("1.0.0"),
			},
			wantErr: false,
		},
		{
			name: "metadata with jwks instead of jwks_uri",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"jwks": {
					"keys": [{
						"kty": "RSA",
						"rsa_params": {
							"n": "example-modulus",
							"e": "AQAB"
						}
					}]
				}
			}`,
			want: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretBasic),
				GrantTypes:              []string{GrantTypesAuthorizationCode},
				ResponseTypes:           []string{ResponseTypesCode},
				Jwks: &JsonWebKeySet{
					Keys: []*JsonWebKey{{
						Kty: "RSA",
						KeyTypeParameters: &JsonWebKey_RsaParams{
							RsaParams: &RsaKeyParameters{
								N: "example-modulus",
								E: "AQAB",
							},
						},
					}},
				},
			},
			wantErr: false,
		},
		{
			name: "explicit token_endpoint_auth_method none",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"token_endpoint_auth_method": "none"
			}`,
			want: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String("none"),
				GrantTypes:              []string{GrantTypesAuthorizationCode},
				ResponseTypes:           []string{ResponseTypesCode},
			},
			wantErr: false,
		},
		{
			name: "custom grant and response types",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"grant_types": ["implicit", "client_credentials"],
				"response_types": ["token", "code"]
			}`,
			want: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretBasic),
				GrantTypes:              []string{"implicit", "client_credentials"},
				ResponseTypes:           []string{"token", "code"},
			},
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   `{"redirect_uris": [}`,
			wantErr: true,
		},
		{
			name: "missing required redirect_uris",
			input: `{
				"client_name": "Test Client"
			}`,
			wantErr: true,
		},
		{
			name: "empty redirect_uris array",
			input: `{
				"redirect_uris": []
			}`,
			wantErr: true,
		},
		{
			name: "invalid redirect_uri",
			input: `{
				"redirect_uris": ["not-a-uri"]
			}`,
			wantErr: true,
		},
		{
			name: "invalid token_endpoint_auth_method",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"token_endpoint_auth_method": "invalid_method"
			}`,
			wantErr: true,
		},
		{
			name: "invalid email in contacts",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"contacts": ["not-an-email"]
			}`,
			wantErr: true,
		},
		{
			name: "invalid scope format",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"scope": "  invalid  spaces  "
			}`,
			wantErr: true,
		},
		{
			name: "both jwks and jwks_uri provided",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"jwks_uri": "https://example.com/.well-known/jwks.json",
				"jwks": {
					"keys": [{
						"kty": "RSA",
						"rsa_params": {
							"n": "example-modulus",
							"e": "AQAB"
						}
					}]
				}
			}`,
			wantErr: true,
		},
		{
			name: "client_name too long",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"client_name": "` + strings.Repeat("a", 256) + `"
			}`,
			wantErr: true,
		},
		{
			name: "discard unknown fields",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"unknown_field": "should be ignored",
				"another_unknown": 123
			}`,
			want: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretBasic),
				GrantTypes:              []string{GrantTypesAuthorizationCode},
				ResponseTypes:           []string{ResponseTypesCode},
			},
			wantErr: false,
		},
		{
			name: "invalid BCP 47 language tag - segment too long",
			input: `{
				"redirect_uris": ["https://example.com/callback"],
				"client_name_localized": {"toolongtagsegment": "Test Client"}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMetadata([]byte(tt.input))
			if err == nil && got != nil {
				got.SetDefaults()
				err = got.Validate()
			}

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("ParseMetadata() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWriteRegistrationResponse(t *testing.T) {
	// Test timestamp for consistent testing
	testTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	testTimestamp := timestamppb.New(testTime)

	tests := []struct {
		name         string
		clientID     string
		clientSecret *ClientSecret
		metadata     *Metadata
		want         map[string]any
		wantErr      bool
	}{
		{
			name:     "minimal response without client secret",
			clientID: "test-client-123",
			metadata: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodNone),
				GrantTypes:              []string{GrantTypesAuthorizationCode},
				ResponseTypes:           []string{ResponseTypesCode},
			},
			want: map[string]any{
				"client_id":                  "test-client-123",
				"redirect_uris":              []any{"https://example.com/callback"},
				"token_endpoint_auth_method": TokenEndpointAuthMethodNone,
				"grant_types":                []any{GrantTypesAuthorizationCode},
				"response_types":             []any{ResponseTypesCode},
			},
		},
		{
			name:     "response with client secret and timestamps",
			clientID: "test-client-456",
			clientSecret: &ClientSecret{
				Value:     "super-secret-value",
				CreatedAt: testTimestamp,
				ExpiresAt: timestamppb.New(testTime.Add(24 * time.Hour)),
			},
			metadata: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretPost),
				GrantTypes:              []string{GrantTypesAuthorizationCode, GrantTypesRefreshToken},
				ResponseTypes:           []string{ResponseTypesCode},
				ClientName:              proto.String("Test Client"),
				Scope:                   proto.String("openid profile email"),
			},
			want: map[string]any{
				"client_id":                  "test-client-456",
				"client_secret":              "super-secret-value",
				"client_id_issued_at":        float64(testTime.Unix()),
				"client_secret_expires_at":   float64(testTime.Add(24 * time.Hour).Unix()),
				"redirect_uris":              []any{"https://example.com/callback"},
				"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretPost,
				"grant_types":                []any{GrantTypesAuthorizationCode, GrantTypesRefreshToken},
				"response_types":             []any{ResponseTypesCode},
				"client_name":                "Test Client",
				"scope":                      "openid profile email",
			},
		},
		{
			name:     "response with client secret but no timestamps",
			clientID: "test-client-789",
			clientSecret: &ClientSecret{
				Value: "another-secret",
				// CreatedAt and ExpiresAt are nil
			},
			metadata: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretBasic),
				GrantTypes:              []string{GrantTypesClientCredentials},
				ResponseTypes:           []string{ResponseTypesCode},
			},
			want: map[string]any{
				"client_id":                  "test-client-789",
				"client_secret":              "another-secret",
				"client_secret_expires_at":   float64(0), // Required per RFC when client_secret is present
				"redirect_uris":              []any{"https://example.com/callback"},
				"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretBasic,
				"grant_types":                []any{GrantTypesClientCredentials},
				"response_types":             []any{ResponseTypesCode},
			},
		},
		{
			name:     "response with full metadata",
			clientID: "full-client-id",
			clientSecret: &ClientSecret{
				Value:     "full-secret",
				CreatedAt: testTimestamp,
			},
			metadata: &Metadata{
				RedirectUris:            []string{"https://example.com/cb1", "https://example.com/cb2"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodClientSecretPost),
				GrantTypes:              []string{GrantTypesAuthorizationCode, GrantTypesImplicit},
				ResponseTypes:           []string{ResponseTypesCode, ResponseTypeToken},
				ClientName:              proto.String("Full Test Client"),
				ClientNameLocalized: map[string]string{
					"en": "Full Test Client",
					"es": "Cliente de Prueba Completo",
				},
				ClientUri: proto.String("https://example.com"),
				ClientUriLocalized: map[string]string{
					"en": "https://example.com/en",
				},
				LogoUri:         proto.String("https://example.com/logo.png"),
				Scope:           proto.String("openid profile email offline_access"),
				Contacts:        []string{"admin@example.com", "support@example.com"},
				TosUri:          proto.String("https://example.com/tos"),
				PolicyUri:       proto.String("https://example.com/privacy"),
				JwksUri:         proto.String("https://example.com/.well-known/jwks.json"),
				SoftwareId:      proto.String("test-software-v1"),
				SoftwareVersion: proto.String("1.2.3"),
			},
			want: map[string]any{
				"client_id":                  "full-client-id",
				"client_secret":              "full-secret",
				"client_id_issued_at":        float64(testTime.Unix()),
				"client_secret_expires_at":   float64(0), // Required per RFC, 0 means no expiration
				"redirect_uris":              []any{"https://example.com/cb1", "https://example.com/cb2"},
				"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretPost,
				"grant_types":                []any{GrantTypesAuthorizationCode, GrantTypesImplicit},
				"response_types":             []any{ResponseTypesCode, ResponseTypeToken},
				"client_name":                "Full Test Client",
				"client_name_localized": map[string]any{
					"en": "Full Test Client",
					"es": "Cliente de Prueba Completo",
				},
				"client_uri": "https://example.com",
				"client_uri_localized": map[string]any{
					"en": "https://example.com/en",
				},
				"logo_uri":         "https://example.com/logo.png",
				"scope":            "openid profile email offline_access",
				"contacts":         []any{"admin@example.com", "support@example.com"},
				"tos_uri":          "https://example.com/tos",
				"policy_uri":       "https://example.com/privacy",
				"jwks_uri":         "https://example.com/.well-known/jwks.json",
				"software_id":      "test-software-v1",
				"software_version": "1.2.3",
			},
		},
		{
			name:     "response with jwks instead of jwks_uri",
			clientID: "jwks-client",
			metadata: &Metadata{
				RedirectUris:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: proto.String(TokenEndpointAuthMethodNone),
				GrantTypes:              []string{GrantTypesAuthorizationCode},
				ResponseTypes:           []string{ResponseTypesCode},
				Jwks: &JsonWebKeySet{
					Keys: []*JsonWebKey{{
						Kty: "RSA",
						KeyTypeParameters: &JsonWebKey_RsaParams{
							RsaParams: &RsaKeyParameters{
								N: "example-modulus",
								E: "AQAB",
							},
						},
					}},
				},
			},
			want: map[string]any{
				"client_id":                  "jwks-client",
				"redirect_uris":              []any{"https://example.com/callback"},
				"token_endpoint_auth_method": TokenEndpointAuthMethodNone,
				"grant_types":                []any{GrantTypesAuthorizationCode},
				"response_types":             []any{ResponseTypesCode},
				"jwks": map[string]any{
					"keys": []any{
						map[string]any{
							"kty": "RSA",
							"rsa_params": map[string]any{
								"n": "example-modulus",
								"e": "AQAB",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteRegistrationResponse(&buf, tt.clientID, tt.clientSecret, tt.metadata)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Parse the JSON output
			var got map[string]any
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("failed to parse JSON output: %v", err)
			}

			// Compare the result
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("WriteRegistrationResponse() mismatch (-want +got):\n%s", diff)
			}

			// Verify that the output is valid JSON
			if !json.Valid(buf.Bytes()) {
				t.Error("output is not valid JSON")
			}

			// Verify that client_secret is only present when expected
			_, hasClientSecret := got["client_secret"]
			expectedHasSecret := tt.clientSecret != nil
			if hasClientSecret != expectedHasSecret {
				t.Errorf("client_secret presence mismatch: got %v, want %v", hasClientSecret, expectedHasSecret)
			}

			// Verify timestamp fields presence per RFC 7591
			_, hasIssuedAt := got["client_id_issued_at"]
			_, hasExpiresAt := got["client_secret_expires_at"]

			expectedHasIssuedAt := tt.clientSecret != nil && tt.clientSecret.CreatedAt != nil
			// Per RFC 7591: client_secret_expires_at is REQUIRED if client_secret is issued
			expectedHasExpiresAt := tt.clientSecret != nil

			if hasIssuedAt != expectedHasIssuedAt {
				t.Errorf("client_id_issued_at presence mismatch: got %v, want %v", hasIssuedAt, expectedHasIssuedAt)
			}
			if hasExpiresAt != expectedHasExpiresAt {
				t.Errorf("client_secret_expires_at presence mismatch: got %v, want %v", hasExpiresAt, expectedHasExpiresAt)
			}
		})
	}
}

func TestWriteRegistrationResponseEdgeCases(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteRegistrationResponse(&buf, "test-client", nil, nil)
		if err == nil {
			t.Fatalf("expected error with nil metadata: %v", err)
		}
	})

	t.Run("empty client ID", func(t *testing.T) {
		var buf bytes.Buffer
		metadata := &Metadata{
			RedirectUris: []string{"https://example.com/callback"},
		}
		err := WriteRegistrationResponse(&buf, "", nil, metadata)
		if err != nil {
			t.Fatalf("unexpected error with empty client ID: %v", err)
		}

		var got map[string]any
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if got["client_id"] != "" {
			t.Errorf("expected empty client_id, got %v", got["client_id"])
		}
	})
}
