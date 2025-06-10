package mcp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func TestCheckTokenRequestAuthorization(t *testing.T) {
	// Test helpers
	newClientRegistration := func(authMethod string, clientSecret *rfc7591v1.ClientSecret) *rfc7591v1.ClientRegistration {
		return &rfc7591v1.ClientRegistration{
			ResponseMetadata: &rfc7591v1.Metadata{
				TokenEndpointAuthMethod: proto.String(authMethod),
			},
			ClientSecret: clientSecret,
		}
	}

	newTokenRequest := func(clientSecret *string) *oauth21proto.TokenRequest {
		return &oauth21proto.TokenRequest{
			ClientSecret: clientSecret,
		}
	}

	newAuthRequest := func(clientID string) *oauth21proto.AuthorizationRequest {
		return &oauth21proto.AuthorizationRequest{
			ClientId: clientID,
		}
	}

	newHTTPRequest := func(basicAuth bool, username, password string) *http.Request {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if basicAuth {
			req.SetBasicAuth(username, password)
		}

		return req
	}

	validSecret := &rfc7591v1.ClientSecret{
		Value: "valid-secret",
	}

	expiredSecret := &rfc7591v1.ClientSecret{
		Value:     "expired-secret",
		ExpiresAt: timestamppb.New(time.Now().Add(-1 * time.Hour)), // expired 1 hour ago
	}

	futureExpirySecret := &rfc7591v1.ClientSecret{
		Value:     "future-secret",
		ExpiresAt: timestamppb.New(time.Now().Add(1 * time.Hour)), // expires in 1 hour
	}

	t.Run("none authentication method", func(t *testing.T) {
		t.Run("should succeed without client secret", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodNone, nil)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})

		t.Run("should succeed even with client secret present", func(t *testing.T) {
			// According to OAuth 2.1, 'none' method means no authentication is required
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodNone, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})
	})

	t.Run("client_secret_basic authentication method", func(t *testing.T) {
		t.Run("should succeed with valid basic auth", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(true, "test-client", "valid-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})

		t.Run("should fail when client secret is missing", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, nil)
			req := newHTTPRequest(true, "test-client", "secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client registration does not have a client secret")
		})

		t.Run("should fail when client secret is expired", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, expiredSecret)
			req := newHTTPRequest(true, "test-client", "expired-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client registration client secret has expired")
		})

		t.Run("should succeed when client secret expires in future", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, futureExpirySecret)
			req := newHTTPRequest(true, "test-client", "future-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})

		t.Run("should fail when basic auth is missing", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "missing client credentials in request")
		})

		t.Run("should fail when client ID mismatch", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(true, "wrong-client", "valid-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client ID mismatch")
			assert.Contains(t, err.Error(), "wrong-client != test-client")
		})

		t.Run("should fail when client secret mismatch", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(true, "test-client", "wrong-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client secret mismatch")
		})
	})

	t.Run("client_secret_post authentication method", func(t *testing.T) {
		t.Run("should succeed with valid client secret in request body", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String("valid-secret"))
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})

		t.Run("should fail when client secret is missing from client registration", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, nil)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String("some-secret"))
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client registration does not have a client secret")
		})

		t.Run("should fail when client secret is expired", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, expiredSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String("expired-secret"))
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client registration client secret has expired")
		})

		t.Run("should succeed when client secret expires in future", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, futureExpirySecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String("future-secret"))
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})

		t.Run("should fail when client secret is missing from request body", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "when using client_secret_post, the client_secret must be provided in the request body")
		})

		t.Run("should fail when client secret mismatch", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String("wrong-secret"))
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client secret mismatch")
		})
	})

	t.Run("unsupported authentication method", func(t *testing.T) {
		t.Run("should fail with unsupported auth method", func(t *testing.T) {
			clientReg := newClientRegistration("unsupported_method", validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported token endpoint authentication method: unsupported_method")
		})
	})

	t.Run("OAuth 2.1 compliance edge cases", func(t *testing.T) {
		t.Run("should handle empty client ID properly", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(true, "", "valid-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err) // Should succeed as both are empty
		})

		t.Run("should handle client_secret_basic with empty basic auth username", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(true, "", "valid-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client ID mismatch")
		})

		t.Run("should handle client_secret_post with empty string secret", func(t *testing.T) {
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String(""))
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client secret mismatch")
		})
	})

	t.Run("OAuth 2.1 Section 3.2.1 compliance", func(t *testing.T) {
		// Tests based on OAuth 2.1 specification section 3.2.1 (Client Authentication)

		t.Run("client_secret_basic MUST authenticate using HTTP Basic", func(t *testing.T) {
			// Per OAuth 2.1, client_secret_basic MUST use HTTP Basic authentication
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, validSecret)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(proto.String("valid-secret")) // Secret in body should be ignored
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "missing client credentials in request")
		})

		t.Run("client_secret_post MUST include secret in request body", func(t *testing.T) {
			// Per OAuth 2.1, client_secret_post MUST include client_secret in request body
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretPost, validSecret)
			req := newHTTPRequest(true, "test-client", "valid-secret") // Basic auth should be ignored
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "when using client_secret_post, the client_secret must be provided in the request body")
		})

		t.Run("none method MUST NOT require client authentication", func(t *testing.T) {
			// Per OAuth 2.1, 'none' method means no client authentication is performed
			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodNone, nil)
			req := newHTTPRequest(false, "", "")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})
	})

	t.Run("security considerations", func(t *testing.T) {
		t.Run("should reject authentication when secret is exactly at expiry time", func(t *testing.T) {
			// Edge case: secret expires exactly now
			nowSecret := &rfc7591v1.ClientSecret{
				Value:     "now-secret",
				ExpiresAt: timestamppb.New(time.Now()),
			}

			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, nowSecret)
			req := newHTTPRequest(true, "test-client", "now-secret")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			// Small delay to ensure time has passed
			time.Sleep(1 * time.Millisecond)

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "client registration client secret has expired")
		})

		t.Run("should handle nil expiration time as never expires", func(t *testing.T) {
			neverExpiringSecret := &rfc7591v1.ClientSecret{
				Value:     "never-expires",
				ExpiresAt: nil, // nil means never expires
			}

			clientReg := newClientRegistration(rfc7591v1.TokenEndpointAuthMethodClientSecretBasic, neverExpiringSecret)
			req := newHTTPRequest(true, "test-client", "never-expires")
			tokenReq := newTokenRequest(nil)
			authReq := newAuthRequest("test-client")

			err := CheckTokenRequestAuthorization(req, clientReg, authReq, tokenReq)
			assert.NoError(t, err)
		})
	})
}
