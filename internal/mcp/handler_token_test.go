package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	identitystate "github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

func TestCreateTokenResponse(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	srv := &Handler{
		cipher: testCipher,
	}

	sessionID := "test-session-id"
	clientID := "test-client-id"
	refreshTokenRecordID := "test-refresh-token-record-id"
	sessionExpiresAt := time.Now().Add(1 * time.Hour)

	createRefreshTokenRecord := func(scopes []string) *oauth21proto.MCPRefreshToken {
		return &oauth21proto.MCPRefreshToken{
			Id:        refreshTokenRecordID,
			UserId:    "test-user-id",
			ClientId:  clientID,
			IssuedAt:  timestamppb.Now(),
			ExpiresAt: timestamppb.New(time.Now().Add(RefreshTokenTTL)),
			Scopes:    scopes,
		}
	}

	t.Run("creates token response with scopes", func(t *testing.T) {
		scopes := []string{"openid", "profile"}
		refreshTokenRecord := createRefreshTokenRecord(scopes)

		resp, err := srv.createTokenResponse(sessionID, sessionExpiresAt, refreshTokenRecord, scopes)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.NotNil(t, resp.ExpiresIn)
		assert.Greater(t, *resp.ExpiresIn, int64(0))
		assert.NotNil(t, resp.RefreshToken)
		assert.NotEmpty(t, *resp.RefreshToken)
		assert.NotNil(t, resp.Scope)
		assert.Equal(t, "openid profile", *resp.Scope)
	})

	t.Run("creates token response without scopes", func(t *testing.T) {
		refreshTokenRecord := createRefreshTokenRecord(nil)

		resp, err := srv.createTokenResponse(sessionID, sessionExpiresAt, refreshTokenRecord, nil)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.NotNil(t, resp.ExpiresIn)
		assert.NotNil(t, resp.RefreshToken)
		assert.Nil(t, resp.Scope)
	})

	t.Run("access token can be decrypted", func(t *testing.T) {
		refreshTokenRecord := createRefreshTokenRecord(nil)

		resp, err := srv.createTokenResponse(sessionID, sessionExpiresAt, refreshTokenRecord, nil)
		require.NoError(t, err)

		// Verify the access token can be decrypted and contains the session ID
		decodedSessionID, err := srv.GetSessionIDFromAccessToken(resp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, sessionID, decodedSessionID)
	})

	t.Run("refresh token can be decrypted", func(t *testing.T) {
		refreshTokenRecord := createRefreshTokenRecord(nil)

		resp, err := srv.createTokenResponse(sessionID, sessionExpiresAt, refreshTokenRecord, nil)
		require.NoError(t, err)

		// Verify the refresh token can be decrypted and contains the refresh token record ID
		code, err := srv.DecryptRefreshToken(*resp.RefreshToken, clientID)
		require.NoError(t, err)
		assert.Equal(t, refreshTokenRecordID, code.Id)
	})

	t.Run("refresh token bound to client", func(t *testing.T) {
		refreshTokenRecord := createRefreshTokenRecord(nil)

		resp, err := srv.createTokenResponse(sessionID, sessionExpiresAt, refreshTokenRecord, nil)
		require.NoError(t, err)

		// Trying to decrypt with wrong client ID should fail
		_, err = srv.DecryptRefreshToken(*resp.RefreshToken, "wrong-client-id")
		assert.Error(t, err)
	})
}

func TestWriteTokenResponse(t *testing.T) {
	t.Run("writes valid JSON response", func(t *testing.T) {
		resp := &oauth21proto.TokenResponse{
			AccessToken:  "test-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    ptrInt64(3600),
			RefreshToken: ptrString("test-refresh-token"),
			Scope:        ptrString("openid profile"),
		}

		w := httptest.NewRecorder()
		writeTokenResponse(w, resp)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", w.Header().Get("Pragma"))

		var decoded map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &decoded)
		require.NoError(t, err)

		assert.Equal(t, "test-access-token", decoded["access_token"])
		assert.Equal(t, "Bearer", decoded["token_type"])
		assert.Equal(t, float64(3600), decoded["expires_in"])
		assert.Equal(t, "test-refresh-token", decoded["refresh_token"])
		assert.Equal(t, "openid profile", decoded["scope"])
	})

	t.Run("writes response without optional fields", func(t *testing.T) {
		resp := &oauth21proto.TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
		}

		w := httptest.NewRecorder()
		writeTokenResponse(w, resp)

		assert.Equal(t, 200, w.Code)

		var decoded map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &decoded)
		require.NoError(t, err)

		assert.Equal(t, "test-access-token", decoded["access_token"])
		assert.Equal(t, "Bearer", decoded["token_type"])
		_, hasExpiresIn := decoded["expires_in"]
		assert.False(t, hasExpiresIn)
	})
}

func ptrInt64(v int64) *int64 {
	return &v
}

func ptrString(v string) *string {
	return &v
}

// setupTestDatabroker creates a test databroker server and returns a storage instance
func setupTestDatabroker(ctx context.Context, t *testing.T) *Storage {
	t.Helper()

	list := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() {
		list.Close()
	})

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	grpcServer := grpc.NewServer()
	databroker_grpc.RegisterDataBrokerServiceServer(grpcServer, srv)

	go func() {
		if err := grpcServer.Serve(list); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
	})

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return list.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	client := databroker_grpc.NewDataBrokerServiceClient(conn)
	return NewStorage(client)
}

func TestTokenHandler_StoresRefreshToken(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	srv := &Handler{
		cipher:  testCipher,
		storage: storage,
	}

	// Setup: Create a client registration
	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{
			TokenEndpointAuthMethod: proto.String("none"),
		},
	})
	require.NoError(t, err)

	// Setup: Create a session
	testSession := session.Create("test-idp", "test-session-id", "test-user-id", time.Now(), 24*time.Hour)
	testSession.OauthToken = &session.OAuthToken{
		RefreshToken: "upstream-refresh-token",
	}
	err = storage.PutSession(ctx, testSession)
	require.NoError(t, err)

	// Setup: Create an authorization request
	codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce"
	codeChallenge := computeS256Challenge(codeVerifier)
	authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
		ClientId:            clientID,
		SessionId:           testSession.Id,
		CodeChallenge:       proto.String(codeChallenge),
		CodeChallengeMethod: proto.String("S256"),
		Scopes:              []string{"openid"},
	})
	require.NoError(t, err)

	// Create an authorization code
	authCode, err := CreateCode(CodeTypeAuthorization, authReqID, time.Now().Add(time.Hour), clientID, testCipher)
	require.NoError(t, err)

	// Make token request
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	srv.Token(w, req)

	// Verify response
	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())

	var tokenResp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &tokenResp)
	require.NoError(t, err)

	refreshToken, ok := tokenResp["refresh_token"].(string)
	require.True(t, ok, "expected refresh_token in response")
	require.NotEmpty(t, refreshToken)

	// Decrypt refresh token to get the record ID
	code, err := srv.DecryptRefreshToken(refreshToken, clientID)
	require.NoError(t, err)

	// Verify refresh token was stored in databroker
	storedToken, err := storage.GetMCPRefreshToken(ctx, code.Id)
	require.NoError(t, err, "refresh token should be stored in databroker")
	assert.Equal(t, clientID, storedToken.ClientId)
	assert.Equal(t, testSession.UserId, storedToken.UserId)
	assert.Equal(t, "upstream-refresh-token", storedToken.UpstreamRefreshToken)
	assert.Equal(t, []string{"openid"}, storedToken.Scopes)
	assert.False(t, storedToken.Revoked)
}

func computeS256Challenge(verifier string) string {
	sha256Hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha256Hash[:])
}

func TestRefreshTokenGrant(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	// Setup: Create a client registration
	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{
			TokenEndpointAuthMethod: proto.String("none"),
		},
	})
	require.NoError(t, err)

	t.Run("successful refresh token exchange", func(t *testing.T) {
		mockAuth := &mockAuthenticator{
			refreshFunc: func(_ context.Context, _ *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: "fresh-refresh-token",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}

		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
			getAuthenticator: func(_ context.Context, _ string) (identity.Authenticator, error) {
				return mockAuth, nil
			},
		}

		// Create a refresh token record
		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "test-refresh-token-id",
			UserId:               "test-user-id",
			ClientId:             clientID,
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
			Scopes:               []string{"openid"},
		}
		err := storage.PutMCPRefreshToken(ctx, refreshTokenRecord)
		require.NoError(t, err)

		// Create encrypted refresh token
		refreshToken, err := srv.CreateRefreshToken(refreshTokenRecord.Id, clientID, refreshTokenRecord.ExpiresAt.AsTime())
		require.NoError(t, err)

		// Make refresh token request
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		srv.Token(w, req)

		require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())

		var tokenResp map[string]any
		err = json.Unmarshal(w.Body.Bytes(), &tokenResp)
		require.NoError(t, err)

		// Verify new tokens were issued
		newAccessToken, ok := tokenResp["access_token"].(string)
		require.True(t, ok, "expected access_token in response")
		require.NotEmpty(t, newAccessToken)

		newRefreshToken, ok := tokenResp["refresh_token"].(string)
		require.True(t, ok, "expected refresh_token in response")
		require.NotEmpty(t, newRefreshToken)
		assert.NotEqual(t, refreshToken, newRefreshToken, "refresh token should be rotated")

		// Verify old refresh token was revoked
		oldRecord, err := storage.GetMCPRefreshToken(ctx, refreshTokenRecord.Id)
		require.NoError(t, err)
		assert.True(t, oldRecord.Revoked, "old refresh token should be revoked")
	})

	t.Run("revoked refresh token fails", func(t *testing.T) {
		srv := &Handler{
			cipher:  testCipher,
			storage: storage,
		}

		// Create a revoked refresh token record
		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "revoked-refresh-token-id",
			UserId:               "test-user-id",
			ClientId:             clientID,
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
			Revoked:              true, // Already revoked
		}
		err := storage.PutMCPRefreshToken(ctx, refreshTokenRecord)
		require.NoError(t, err)

		refreshToken, err := srv.CreateRefreshToken(refreshTokenRecord.Id, clientID, refreshTokenRecord.ExpiresAt.AsTime())
		require.NoError(t, err)

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		srv.Token(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("expired refresh token fails", func(t *testing.T) {
		srv := &Handler{
			cipher:  testCipher,
			storage: storage,
		}

		// Create an expired refresh token record
		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "expired-refresh-token-id",
			UserId:               "test-user-id",
			ClientId:             clientID,
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.New(time.Now().Add(-2 * time.Hour)),
			ExpiresAt:            timestamppb.New(time.Now().Add(-1 * time.Hour)), // Expired
		}
		err := storage.PutMCPRefreshToken(ctx, refreshTokenRecord)
		require.NoError(t, err)

		// Create refresh token with future expiry so it can be decrypted
		refreshToken, err := srv.CreateRefreshToken(refreshTokenRecord.Id, clientID, time.Now().Add(time.Hour))
		require.NoError(t, err)

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		srv.Token(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("wrong client_id fails", func(t *testing.T) {
		srv := &Handler{
			cipher:  testCipher,
			storage: storage,
		}

		// Create another client
		otherClientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
			ResponseMetadata: &rfc7591v1.Metadata{
				TokenEndpointAuthMethod: proto.String("none"),
			},
		})
		require.NoError(t, err)

		// Create a refresh token record for the original client
		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "wrong-client-refresh-token-id",
			UserId:               "test-user-id",
			ClientId:             clientID, // Original client
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}
		err = storage.PutMCPRefreshToken(ctx, refreshTokenRecord)
		require.NoError(t, err)

		// Create refresh token bound to original client
		refreshToken, err := srv.CreateRefreshToken(refreshTokenRecord.Id, clientID, refreshTokenRecord.ExpiresAt.AsTime())
		require.NoError(t, err)

		// Try to use with different client_id - decryption should fail because token is bound to original client
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {otherClientID}, // Different client
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		srv.Token(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// mockAuthenticator implements identity.Authenticator for testing
type mockAuthenticator struct {
	refreshFunc func(ctx context.Context, t *oauth2.Token, v identitystate.State) (*oauth2.Token, error)
}

func (m *mockAuthenticator) Authenticate(_ context.Context, _ string, _ identitystate.State) (*oauth2.Token, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthenticator) Refresh(ctx context.Context, t *oauth2.Token, v identitystate.State) (*oauth2.Token, error) {
	if m.refreshFunc != nil {
		return m.refreshFunc(ctx, t, v)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAuthenticator) Revoke(_ context.Context, _ *oauth2.Token) error {
	return errors.New("not implemented")
}

func (m *mockAuthenticator) Name() string {
	return "mock"
}

func (m *mockAuthenticator) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return nil
}

func (m *mockAuthenticator) VerifyAccessToken(_ context.Context, _ string) (map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthenticator) VerifyIdentityToken(_ context.Context, _ string) (map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthenticator) SignIn(_ http.ResponseWriter, _ *http.Request, _ string) error {
	return errors.New("not implemented")
}

func (m *mockAuthenticator) SignOut(_ http.ResponseWriter, _ *http.Request, _, _, _ string) error {
	return errors.New("not implemented")
}

func (m *mockAuthenticator) DeviceAuth(_ context.Context) (*oauth2.DeviceAuthResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthenticator) DeviceAccessToken(_ context.Context, _ *oauth2.DeviceAuthResponse, _ identitystate.State) (*oauth2.Token, error) {
	return nil, errors.New("not implemented")
}

var _ identity.Authenticator = (*mockAuthenticator)(nil)

func TestGetOrRecreateSession(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	t.Run("with successful authenticator refresh", func(t *testing.T) {
		mockAuth := &mockAuthenticator{
			refreshFunc: func(_ context.Context, _ *oauth2.Token, v identitystate.State) (*oauth2.Token, error) {
				// Verify that v is not nil - SessionUnmarshaler should be passed
				if v == nil {
					return nil, errors.New("State should not be nil - NewSessionUnmarshaler should be passed")
				}

				// Simulate IdP setting the raw ID token (this would panic if v was nil)
				v.SetRawIDToken("mock-id-token")

				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: "fresh-refresh-token",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}

		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
			getAuthenticator: func(_ context.Context, idpID string) (identity.Authenticator, error) {
				assert.Equal(t, "test-idp", idpID)
				return mockAuth, nil
			},
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-1",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		newSession, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.NoError(t, err)
		require.NotNil(t, newSession)

		// Verify the session has the fresh OAuth token
		assert.Equal(t, "test-user-id", newSession.UserId)
		assert.Equal(t, "test-idp", newSession.IdpId)
		assert.NotNil(t, newSession.OauthToken)
		assert.Equal(t, "fresh-access-token", newSession.OauthToken.AccessToken)
		assert.Equal(t, "fresh-refresh-token", newSession.OauthToken.RefreshToken)
	})

	t.Run("with successful authenticator refresh populates claims via SessionUnmarshaler", func(t *testing.T) {
		mockAuth := &mockAuthenticator{
			refreshFunc: func(_ context.Context, _ *oauth2.Token, v identitystate.State) (*oauth2.Token, error) {
				// Verify that v is not nil and is a SessionUnmarshaler
				if v == nil {
					return nil, errors.New("State should not be nil - NewSessionUnmarshaler should be passed")
				}

				// Simulate IdP setting the raw ID token - the SessionUnmarshaler will parse it
				// and populate the session's IdToken field
				v.SetRawIDToken("mock-id-token")

				// Simulate IdP calling Claims() to unmarshal additional claims into the session.
				// This is what actually populates the session.Claims map.
				// The SessionUnmarshaler implements json.Unmarshaler.
				claimsJSON := []byte(`{"email": "test@example.com", "groups": ["admin", "users"]}`)
				if unmarshaler, ok := v.(interface{ UnmarshalJSON([]byte) error }); ok {
					if err := unmarshaler.UnmarshalJSON(claimsJSON); err != nil {
						return nil, err
					}
				}

				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: "fresh-refresh-token",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}

		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
			getAuthenticator: func(_ context.Context, idpID string) (identity.Authenticator, error) {
				assert.Equal(t, "test-idp", idpID)
				return mockAuth, nil
			},
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-claims",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		newSession, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.NoError(t, err)
		require.NotNil(t, newSession)

		// Verify the session has the fresh OAuth token
		assert.Equal(t, "test-user-id", newSession.UserId)
		assert.Equal(t, "test-idp", newSession.IdpId)
		assert.NotNil(t, newSession.OauthToken)
		assert.Equal(t, "fresh-access-token", newSession.OauthToken.AccessToken)
		assert.Equal(t, "fresh-refresh-token", newSession.OauthToken.RefreshToken)

		// Verify claims were populated from the ID token via SessionUnmarshaler
		require.NotNil(t, newSession.Claims, "session should have claims populated from upstream IdP")
		assert.Contains(t, newSession.Claims, "email", "email claim should be present")
		assert.Contains(t, newSession.Claims, "groups", "groups claim should be present")
	})

	t.Run("with authenticator refresh error returns error", func(t *testing.T) {
		mockAuth := &mockAuthenticator{
			refreshFunc: func(_ context.Context, _ *oauth2.Token, v identitystate.State) (*oauth2.Token, error) {
				// Still verify v is not nil even when returning an error
				if v == nil {
					return nil, errors.New("State should not be nil")
				}
				return nil, errors.New("upstream IdP unavailable")
			},
		}

		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
			getAuthenticator: func(_ context.Context, _ string) (identity.Authenticator, error) {
				return mockAuth, nil
			},
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-2",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		_, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.Error(t, err, "should fail when upstream refresh fails")
		assert.Contains(t, err.Error(), "failed to refresh upstream token")
		assert.Contains(t, err.Error(), "upstream IdP unavailable")
	})

	t.Run("without authenticator configured returns error", func(t *testing.T) {
		srv := &Handler{
			cipher:           testCipher,
			storage:          storage,
			sessionExpiry:    14 * time.Hour,
			getAuthenticator: nil, // No authenticator configured
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-3",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		_, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.Error(t, err, "should fail when no authenticator is configured")
		assert.Contains(t, err.Error(), "no authenticator configured")
	})

	t.Run("with getAuthenticator returning error returns error", func(t *testing.T) {
		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
			getAuthenticator: func(_ context.Context, _ string) (identity.Authenticator, error) {
				return nil, errors.New("IdP not configured")
			},
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-4",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		_, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.Error(t, err, "should fail when getAuthenticator returns error")
		assert.Contains(t, err.Error(), "failed to get authenticator")
		assert.Contains(t, err.Error(), "IdP not configured")
	})

	t.Run("with nil authenticator returns error", func(t *testing.T) {
		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
			getAuthenticator: func(_ context.Context, _ string) (identity.Authenticator, error) {
				return nil, nil // Returns nil authenticator without error
			},
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-nil-auth",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		_, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.Error(t, err, "should fail when authenticator is nil")
		assert.Contains(t, err.Error(), "authenticator is nil")
	})

	t.Run("without upstream refresh token fails", func(t *testing.T) {
		srv := &Handler{
			cipher:        testCipher,
			storage:       storage,
			sessionExpiry: 14 * time.Hour,
		}

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-5",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "", // No upstream refresh token
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		_, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no upstream refresh token")
	})
}

// TestSessionUnmarshalerInRefresh verifies that NewSessionUnmarshaler properly implements
// identity.State and can receive ID token claims from the upstream IdP during refresh.
func TestSessionUnmarshalerInRefresh(t *testing.T) {
	// Verify NewSessionUnmarshaler implements the State interface
	sess := session.Create("test-idp", "test-session", "test-user", time.Now(), time.Hour)
	var state identitystate.State = manager.NewSessionUnmarshaler(sess)
	require.NotNil(t, state)

	// Verify SetRawIDToken doesn't panic (even with invalid token)
	assert.NotPanics(t, func() {
		state.SetRawIDToken("some-invalid-token")
	})

	// Call it multiple times to ensure stability
	state.SetRawIDToken("")
	state.SetRawIDToken("another-token")

	// Note: With a valid JWT, the ID token would be parsed and set on the session.
	// See pkg/identity/manager/data_test.go TestSession_RefreshUpdate for an example with a valid JWT.
}
