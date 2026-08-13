package mcp

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/idpsession"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	pom_grpc "github.com/pomerium/pomerium/pkg/grpc"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	identitystate "github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/protoutil"
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

		resp, err := srv.createTokenResponse(sessionID, 0, sessionExpiresAt, refreshTokenRecord, scopes)
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

		resp, err := srv.createTokenResponse(sessionID, 0, sessionExpiresAt, refreshTokenRecord, nil)
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

		resp, err := srv.createTokenResponse(sessionID, 0, sessionExpiresAt, refreshTokenRecord, nil)
		require.NoError(t, err)

		// Verify the access token can be decrypted and contains the session ID
		decodedSessionID, err := srv.GetSessionIDFromAccessToken(resp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, sessionID, decodedSessionID)
	})

	t.Run("refresh token can be decrypted", func(t *testing.T) {
		refreshTokenRecord := createRefreshTokenRecord(nil)

		resp, err := srv.createTokenResponse(sessionID, 0, sessionExpiresAt, refreshTokenRecord, nil)
		require.NoError(t, err)

		// Verify the refresh token can be decrypted and contains the refresh token record ID
		code, err := srv.DecryptRefreshToken(*resp.RefreshToken, clientID)
		require.NoError(t, err)
		assert.Equal(t, refreshTokenRecordID, code.Id)
	})

	t.Run("refresh token bound to client", func(t *testing.T) {
		refreshTokenRecord := createRefreshTokenRecord(nil)

		resp, err := srv.createTokenResponse(sessionID, 0, sessionExpiresAt, refreshTokenRecord, nil)
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
			ExpiresIn:    new(int64(3600)),
			RefreshToken: new("test-refresh-token"),
			Scope:        new("openid profile"),
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
			TokenEndpointAuthMethod: new("none"),
		},
	})
	require.NoError(t, err)

	// Setup: Create a session
	testSession := session.Create("test-idp", "test-session-id", "test-user-id", time.Now(), 24*time.Hour)
	testSession.OauthToken = &session.OAuthToken{
		RefreshToken: "upstream-refresh-token",
	}
	_, err = storage.PutSession(ctx, testSession)
	require.NoError(t, err)

	// Setup: Create an authorization request
	codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce"
	codeChallenge := computeS256Challenge(codeVerifier)
	authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
		ClientId:            clientID,
		SessionId:           testSession.Id,
		CodeChallenge:       new(codeChallenge),
		CodeChallengeMethod: new("S256"),
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

// storeWiredHandler builds a Handler the way production does: proxy always
// passes an authenticator getter, so idpStore is always set and the refresh
// grant goes through the shared store. Tests that predate the store were built
// against the legacy fallback, which no deployment reaches.
func storeWiredHandler(storage *Storage, testCipher cipher.AEAD, getAuth AuthenticatorGetter, opts ...idpsession.Option) *Handler {
	return &Handler{
		cipher:           testCipher,
		storage:          storage,
		sessionExpiry:    14 * time.Hour,
		getAuthenticator: getAuth,
		idpStore:         idpsession.New(storage.client, getAuth, opts...),
	}
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
			TokenEndpointAuthMethod: new("none"),
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

		srv := storeWiredHandler(storage, testCipher, func(_ context.Context, _ string) (identity.Authenticator, error) {
			return mockAuth, nil
		})

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

		// The rotated upstream token reaches the new MCP refresh token record,
		// which is what lets the next grant present the right token.
		code, err := srv.DecryptRefreshToken(newRefreshToken, clientID)
		require.NoError(t, err)
		newRecord, err := storage.GetMCPRefreshToken(ctx, code.Id)
		require.NoError(t, err)
		assert.Equal(t, "fresh-refresh-token", newRecord.UpstreamRefreshToken,
			"the rotated upstream token is written back through the store")
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

	// A transient upstream failure must not be reported as a sign-out.
	// invalid_grant tells the client to discard its refresh token and
	// re-authorize, while an IdP outage, or another replica mid-refresh, has to
	// read as "try again with the same token".
	t.Run("transient upstream failure is retryable, not a sign-out", func(t *testing.T) {
		getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
			return &mockAuthenticator{
				refreshFunc: func(_ context.Context, _ *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
					return nil, temporaryUpstreamError{}
				},
			}, nil
		}
		srv := storeWiredHandler(storage, testCipher, getAuth)

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "transient-upstream-refresh-token-id",
			UserId:               "transient-user-id",
			ClientId:             clientID,
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}
		require.NoError(t, storage.PutMCPRefreshToken(ctx, refreshTokenRecord))

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

		require.Equal(t, http.StatusServiceUnavailable, w.Code,
			"a 5xx makes a client retry instead of re-authorizing; body: %s", w.Body.String())
		assert.NotEmpty(t, w.Header().Get("Retry-After"))

		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, string(oauth21.TemporarilyUnavailable), body["error"])

		// The client keeps its refresh token, so the retry it was told to make can
		// succeed.
		stored, err := storage.GetMCPRefreshToken(ctx, refreshTokenRecord.Id)
		require.NoError(t, err)
		assert.False(t, stored.Revoked, "an outage must not consume the client's refresh token")
	})

	t.Run("wrong client_id fails", func(t *testing.T) {
		srv := &Handler{
			cipher:  testCipher,
			storage: storage,
		}

		// Create another client
		otherClientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
			ResponseMetadata: &rfc7591v1.Metadata{
				TokenEndpointAuthMethod: new("none"),
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

	t.Run("concurrent refresh token usage", func(t *testing.T) {
		// This test verifies behavior when multiple clients attempt to use the same
		// refresh token simultaneously (token rotation atomicity).
		//
		// Current behavior: Due to a race condition between checking if a token is
		// revoked and actually revoking it, multiple concurrent requests can all
		// succeed. This is a known limitation - ideally only one should succeed
		// to prevent double-spend of refresh tokens.
		//
		// The test verifies:
		// 1. At least one request succeeds
		// 2. The token is properly revoked after all requests complete
		// 3. All responses are valid (either success or expected failure)

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

		srv := storeWiredHandler(storage, testCipher, func(_ context.Context, _ string) (identity.Authenticator, error) {
			return mockAuth, nil
		})

		// Create a refresh token record
		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id: "concurrent-test-refresh-token-id",
			// Its own user, because the canonical upstream record is keyed by
			// (user, idp): sharing one with an earlier case would serve these
			// grants from that record and never reach the IdP at all.
			UserId:               "concurrent-test-user-id",
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

		// Launch N goroutines attempting to use the same token concurrently
		const numGoroutines = 10
		results := make(chan int, numGoroutines) // channel to collect HTTP status codes
		start := make(chan struct{})             // synchronization channel

		for range numGoroutines {
			go func() {
				// Wait for all goroutines to be ready
				<-start

				form := url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {refreshToken},
					"client_id":     {clientID},
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
				if err != nil {
					results <- http.StatusInternalServerError
					return
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				w := httptest.NewRecorder()
				srv.Token(w, req)
				results <- w.Code
			}()
		}

		// Release all goroutines simultaneously
		close(start)

		// Collect results
		successCount := 0
		failureCount := 0
		retryCount := 0
		for range numGoroutines {
			switch code := <-results; code {
			case http.StatusOK:
				successCount++
			case http.StatusBadRequest:
				failureCount++
			case http.StatusServiceUnavailable:
				// A caller suppressed by the one that went to the IdP is told to
				// retry rather than being refused, which is lawful here.
				retryCount++
			default:
				t.Errorf("unexpected status code: %d", code)
			}
		}

		// Verify at least one succeeds
		assert.GreaterOrEqual(t, successCount, 1, "at least one refresh should succeed")

		// Verify all responses are accounted for
		assert.Equal(t, numGoroutines, successCount+failureCount+retryCount,
			"every request returns success, refusal, or retry")

		// The whole point of the shared store: however many grants raced, the
		// upstream refresh token was presented to the IdP once.
		assert.Equal(t, int64(1), mockAuth.refreshCalls.Load(),
			"concurrent grants collapse to one presentation of the upstream token")
		mockAuth.assertNoReplay(t)

		// Verify the original token is properly revoked
		storedToken, err := storage.GetMCPRefreshToken(ctx, refreshTokenRecord.Id)
		require.NoError(t, err)
		assert.True(t, storedToken.Revoked, "original refresh token should be revoked")

		t.Logf("Concurrent refresh results: %d succeeded, %d refused, %d told to retry",
			successCount, failureCount, retryCount)
	})

	t.Run("storage failure when storing new refresh token returns error", func(t *testing.T) {
		// This test verifies that when storing the new refresh token fails,
		// the request returns an error and the old token remains valid.
		// This is the safe behavior: store new token first, then revoke old.

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

		// Create a mock storage that fails on the first PutMCPRefreshToken call (storing new token)
		storageFailErr := errors.New("simulated storage failure")
		mockStore := &mockStorage{
			Storage: storage,
			putMCPRefreshTokenFunc: func(_ context.Context, _ *oauth21proto.MCPRefreshToken) error {
				return storageFailErr
			},
		}

		getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
			return mockAuth, nil
		}
		srv := &Handler{
			cipher:           testCipher,
			storage:          mockStore,
			sessionExpiry:    14 * time.Hour,
			getAuthenticator: getAuth,
			idpStore:         idpsession.New(storage.client, getAuth),
		}

		// Create a valid refresh token record in the real storage
		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "storage-fail-test-refresh-token-id",
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

		// Should return internal server error
		assert.Equal(t, http.StatusInternalServerError, w.Code, "should return 500 when storage fails")

		// The old token should still be valid (not revoked) since we failed before revoking it
		oldRecord, err := storage.GetMCPRefreshToken(ctx, refreshTokenRecord.Id)
		require.NoError(t, err)
		assert.False(t, oldRecord.Revoked, "old refresh token should NOT be revoked when new token storage fails")
	})
}

// mockAuthenticator implements identity.Authenticator for testing
// temporaryUpstreamError reports Temporary(), which both the idpsession store
// and pkg/identity/manager read as "keep the session and retry" rather than
// "this grant is over".
type temporaryUpstreamError struct{}

func (temporaryUpstreamError) Error() string   { return "upstream temporarily unavailable" }
func (temporaryUpstreamError) Temporary() bool { return true }

type mockAuthenticator struct {
	refreshFunc func(ctx context.Context, t *oauth2.Token, v identitystate.State) (*oauth2.Token, error)

	// refreshCalls counts presentations of the upstream refresh token, so a test
	// can assert that concurrent grants collapse to one.
	refreshCalls atomic.Int64

	// presented records every refresh token value handed to the IdP. Counting
	// calls alone cannot catch a replay, because two calls presenting the same
	// token look like two presenting different ones.
	presentedMu sync.Mutex
	presented   []string
}

// presentedTokens returns the refresh tokens presented so far, in order.
func (m *mockAuthenticator) presentedTokens() []string {
	m.presentedMu.Lock()
	defer m.presentedMu.Unlock()
	return slices.Clone(m.presented)
}

// assertNoReplay fails if any refresh token was presented more than once, which
// is what revokes a whole grant family on a reuse-detecting provider.
func (m *mockAuthenticator) assertNoReplay(t *testing.T) {
	t.Helper()
	seen := map[string]int{}
	for _, tok := range m.presentedTokens() {
		seen[tok]++
	}
	for tok, n := range seen {
		assert.Equal(t, 1, n, "refresh token %q was presented %d times", tok, n)
	}
}

func (m *mockAuthenticator) Authenticate(_ context.Context, _ string, _ identitystate.State) (*oauth2.Token, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthenticator) Refresh(ctx context.Context, t *oauth2.Token, v identitystate.State) (*oauth2.Token, error) {
	m.refreshCalls.Add(1)
	m.presentedMu.Lock()
	m.presented = append(m.presented, t.RefreshToken)
	m.presentedMu.Unlock()
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

// mockStorage wraps a real storage and allows injecting errors for specific operations.
type mockStorage struct {
	*Storage
	putMCPRefreshTokenFunc func(ctx context.Context, token *oauth21proto.MCPRefreshToken) error
}

func (m *mockStorage) PutMCPRefreshToken(ctx context.Context, token *oauth21proto.MCPRefreshToken) error {
	if m.putMCPRefreshTokenFunc != nil {
		return m.putMCPRefreshTokenFunc(ctx, token)
	}
	return m.Storage.PutMCPRefreshToken(ctx, token)
}

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

		srv := storeWiredHandler(storage, testCipher, func(_ context.Context, idpID string) (identity.Authenticator, error) {
			assert.Equal(t, "test-idp", idpID)
			return mockAuth, nil
		})

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id:                   "session-test-1",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		newSession, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
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

		srv := storeWiredHandler(storage, testCipher, func(_ context.Context, idpID string) (identity.Authenticator, error) {
			assert.Equal(t, "test-idp", idpID)
			return mockAuth, nil
		})

		refreshTokenRecord := &oauth21proto.MCPRefreshToken{
			Id: "session-test-claims",
			// A distinct user, because the canonical upstream record is keyed by
			// (user, idp): sharing one with the previous case would serve this one
			// from that record instead of refreshing.
			UserId:               "test-user-claims",
			ClientId:             "test-client-id",
			IdpId:                "test-idp",
			UpstreamRefreshToken: "upstream-refresh-token",
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}

		newSession, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
		require.NoError(t, err)
		require.NotNil(t, newSession)

		// Verify the session has the fresh OAuth token
		assert.Equal(t, "test-user-claims", newSession.UserId)
		assert.Equal(t, "test-idp", newSession.IdpId)
		assert.NotNil(t, newSession.OauthToken)
		assert.Equal(t, "fresh-access-token", newSession.OauthToken.AccessToken)
		assert.Equal(t, "fresh-refresh-token", newSession.OauthToken.RefreshToken)

		// Verify claims were populated from the ID token via SessionUnmarshaler
		require.NotNil(t, newSession.Claims, "session should have claims populated from upstream IdP")
		assert.Contains(t, newSession.Claims, "email", "email claim should be present")
		assert.Contains(t, newSession.Claims, "groups", "groups claim should be present")
	})

	// The remaining cases pin the legacy fallback, which runs only when no
	// authenticator getter is wired and therefore no store exists. Production
	// always wires one, so these cover code that no deployment reaches; they stay
	// while that fallback does.
	t.Run("legacy path: with authenticator refresh error returns error", func(t *testing.T) {
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

		_, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
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

		_, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
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

		_, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
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

		_, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
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

		_, _, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
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

// TestRefreshTokenGrant_DatabrokerFailureIsRetryable: the store reports
// databroker failures as typed gRPC status errors, which do not implement
// Temporary(). Reported as invalid_grant they would tell every MCP client of the
// user to discard a refresh token that is still valid, and only a new login
// could undo that.
func TestRefreshTokenGrant_DatabrokerFailureIsRetryable(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{TokenEndpointAuthMethod: new("none")},
	})
	require.NoError(t, err)

	getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return &mockAuthenticator{}, nil
	}

	for _, code := range []codes.Code{
		codes.Unavailable, codes.Aborted, codes.DeadlineExceeded, codes.Internal, codes.FailedPrecondition,
	} {
		t.Run(code.String(), func(t *testing.T) {
			broken := dbtestutil.FailingDatabroker(storage.client, status.Error(code, "databroker is having a bad day"))
			srv := &Handler{
				cipher:           testCipher,
				storage:          storage,
				sessionExpiry:    14 * time.Hour,
				getAuthenticator: getAuth,
				idpStore:         idpsession.New(broken, getAuth),
			}

			refreshTokenRecord := &oauth21proto.MCPRefreshToken{
				Id:                   "databroker-failure-" + code.String(),
				UserId:               "user-" + code.String(),
				ClientId:             clientID,
				IdpId:                "test-idp",
				UpstreamRefreshToken: "upstream-refresh-token",
				IssuedAt:             timestamppb.Now(),
				ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
			}
			require.NoError(t, storage.PutMCPRefreshToken(ctx, refreshTokenRecord))

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

			require.Equal(t, http.StatusServiceUnavailable, w.Code,
				"a databroker failure must not be reported as a refused grant; body: %s", w.Body.String())
			assert.NotEmpty(t, w.Header().Get("Retry-After"))

			var body map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, string(oauth21.TemporarilyUnavailable), body["error"])

			stored, err := storage.GetMCPRefreshToken(ctx, refreshTokenRecord.Id)
			require.NoError(t, err)
			assert.False(t, stored.Revoked, "the client's refresh token survives an infrastructure failure")
		})
	}
}

// TestRefreshGrantAfterDeath_OnlyALoginRecovers pins the second invariant at the
// endpoint. Once the canonical record is dead, no copy any client holds brings it
// back: every refresh grant is refused, and only a fresh grant installed by the
// login flow restores service.
func TestRefreshGrantAfterDeath_OnlyALoginRecovers(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{TokenEndpointAuthMethod: new("none")},
	})
	require.NoError(t, err)

	// The IdP refuses everything except the token a login would produce.
	getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return &mockAuthenticator{
			refreshFunc: func(_ context.Context, tok *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
				if tok.RefreshToken != "post-login-upstream-token" {
					return nil, &oauth2.RetrieveError{
						Response:  &http.Response{StatusCode: http.StatusBadRequest},
						ErrorCode: "invalid_grant",
					}
				}
				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: tok.RefreshToken,
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}, nil
	}
	srv := storeWiredHandler(storage, testCipher, getAuth)

	const userID, idpID = "death-user-id", "test-idp"
	mint := func(id, upstream string) string {
		rec := &oauth21proto.MCPRefreshToken{
			Id:                   id,
			UserId:               userID,
			ClientId:             clientID,
			IdpId:                idpID,
			UpstreamRefreshToken: upstream,
			IssuedAt:             timestamppb.Now(),
			ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		}
		require.NoError(t, storage.PutMCPRefreshToken(ctx, rec))
		tok, err := srv.CreateRefreshToken(rec.Id, clientID, rec.ExpiresAt.AsTime())
		require.NoError(t, err)
		return tok
	}

	// Client A's copy is refused on its first use, which kills the record.
	clientA := mint("client-a-refresh-token", "stale-upstream-token")
	require.Equal(t, http.StatusBadRequest, postRefreshGrant(ctx, t, srv, clientID, clientA).Code)

	// Client B holds a different copy of the same grant. It is refused too:
	// nothing a client holds may resurrect a dead upstream session.
	clientB := mint("client-b-refresh-token", "another-upstream-token")
	assert.Equal(t, http.StatusBadRequest, postRefreshGrant(ctx, t, srv, clientID, clientB).Code,
		"a second client's copy must not revive a dead record")

	// Completing an authorization does not revive it either; the auth-code grant
	// only seeds a record that is absent.
	w := postAuthCodeGrant(ctx, t, srv, storage, clientID, userID, idpID,
		"death-session-1", "some-browser-copy")
	require.Equal(t, http.StatusOK, w.Code, "seeding never fails the grant; body: %s", w.Body.String())
	assert.Never(t, func() bool {
		_, err := srv.idpStore.EnsureLive(ctx, userID, idpID)
		return err == nil
	}, time.Second, 50*time.Millisecond, "an authorization is not a fresh grant")

	// A login is. This is what internal/authenticateflow does on PersistSession.
	require.NoError(t, srv.idpStore.Supersede(ctx, userID, idpID, "post-login-upstream-token", ""))

	res := postRefreshGrant(ctx, t, srv, clientID, clientB)
	assert.Equal(t, http.StatusOK, res.Code,
		"signing in again restores every client of the user; body: %s", res.Body.String())
}

func postAuthCodeGrant(
	ctx context.Context,
	t *testing.T,
	srv *Handler,
	storage *Storage,
	clientID, userID, idpID, sessionID, upstreamRefreshToken string,
) *httptest.ResponseRecorder {
	t.Helper()
	testSession := session.Create(idpID, sessionID, userID, time.Now(), 24*time.Hour)
	testSession.OauthToken = &session.OAuthToken{RefreshToken: upstreamRefreshToken}
	_, err := storage.PutSession(ctx, testSession)
	require.NoError(t, err)

	codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce"
	codeChallenge := computeS256Challenge(codeVerifier)
	authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
		ClientId:            clientID,
		SessionId:           testSession.Id,
		CodeChallenge:       new(codeChallenge),
		CodeChallengeMethod: new("S256"),
	})
	require.NoError(t, err)
	authCode, err := CreateCode(CodeTypeAuthorization, authReqID, time.Now().Add(time.Hour), clientID, srv.cipher)
	require.NoError(t, err)

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
	return w
}

func postRefreshGrant(ctx context.Context, t *testing.T, srv *Handler, clientID, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
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
	return w
}

// TestRefreshGrantRequiresFreshUpstream: the refresh grant mints a session that
// outlives the answer by hours, so it must not be satisfied by a token that has
// merely not expired. Without this, a revoked user keeps being issued sessions
// until the stored access token runs out.
func TestRefreshGrantRequiresFreshUpstream(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	var refreshes atomic.Int64
	getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return &mockAuthenticator{
			refreshFunc: func(_ context.Context, tok *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
				refreshes.Add(1)
				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: tok.RefreshToken,
					// Long-lived, so only a freshness requirement sends the second
					// grant back to the IdP.
					Expiry: time.Now().Add(24 * time.Hour),
				}, nil
			},
		}, nil
	}
	srv := storeWiredHandler(storage, testCipher, getAuth)

	rec := &oauth21proto.MCPRefreshToken{
		Id:                   "freshness-refresh-token-id",
		UserId:               "freshness-user-id",
		ClientId:             "freshness-client",
		IdpId:                "test-idp",
		UpstreamRefreshToken: "upstream-refresh-token",
		IssuedAt:             timestamppb.Now(),
		ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
	}
	_, _, err = srv.getOrRecreateSession(ctx, rec)
	require.NoError(t, err)
	require.Equal(t, int64(1), refreshes.Load())

	// The stored token is valid for a day, so a caller that accepted any
	// unexpired token would not go back to the IdP here. This one does, because
	// the store was asked for freshness and the debounce window has been
	// bypassed by pointing the handler's store at a zero-length one.
	srv.idpStore = idpsession.New(storage.client, getAuth,
		idpsession.WithMinRefreshInterval(time.Nanosecond))
	_, _, err = srv.getOrRecreateSession(ctx, rec)
	require.NoError(t, err)
	assert.Equal(t, int64(2), refreshes.Load(),
		"the refresh grant rechecks liveness instead of trusting an unexpired token")
}

// TestRefreshGrantOnAnUnreadableRecord: stored bytes that do not parse are an
// operator problem. Nothing may overwrite a record it cannot read, so the grant
// reports a server error rather than telling the client its grant is over, and
// recovery is a login.
func TestRefreshGrantOnAnUnreadableRecord(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{TokenEndpointAuthMethod: new("none")},
	})
	require.NoError(t, err)

	getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return &mockAuthenticator{
			refreshFunc: func(_ context.Context, tok *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: tok.RefreshToken,
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}, nil
	}
	srv := storeWiredHandler(storage, testCipher, getAuth)

	const userID, idpID = "corrupt-record-user", "test-idp"
	corruptID := idpsession.RecordID(userID, idpID)
	data := protoutil.NewAny(&oauth21proto.MCPRefreshToken{Id: corruptID})
	_, err = storage.client.Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{{
		Id:   corruptID,
		Data: data,
		Type: protoutil.GetTypeURL(new(oauth21proto.UpstreamIdPSession)),
	}}})
	require.NoError(t, err)

	rec := &oauth21proto.MCPRefreshToken{
		Id:                   "corrupt-record-refresh-token-id",
		UserId:               userID,
		ClientId:             clientID,
		IdpId:                idpID,
		UpstreamRefreshToken: "upstream-refresh-token",
		IssuedAt:             timestamppb.Now(),
		ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
	}
	require.NoError(t, storage.PutMCPRefreshToken(ctx, rec))
	refreshToken, err := srv.CreateRefreshToken(rec.Id, clientID, rec.ExpiresAt.AsTime())
	require.NoError(t, err)

	res := postRefreshGrant(ctx, t, srv, clientID, refreshToken)
	require.Equal(t, http.StatusInternalServerError, res.Code,
		"unreadable storage is not the client's fault; body: %s", res.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &body))
	assert.Equal(t, string(oauth21.ServerError), body["error"])
	assert.Empty(t, res.Header().Get("Retry-After"), "no interval makes unreadable bytes parse")

	// A login replaces the record, which is the documented way out.
	require.NoError(t, srv.idpStore.Supersede(ctx, userID, idpID, "post-login-upstream-token", ""))
	assert.Equal(t, http.StatusOK, postRefreshGrant(ctx, t, srv, clientID, refreshToken).Code)
}

// TestNewWiresTheUpstreamSessionStore: production always passes an authenticator
// getter, and that is what decides whether the refresh grant uses the shared
// store at all. Nothing else exercises this wiring.
func TestNewWiresTheUpstreamSessionStore(t *testing.T) {
	ctx := context.Background()

	opts := config.NewDefaultOptions()
	opts.SharedKey = base64.StdEncoding.EncodeToString(cryptutil.NewKey())
	cfg := &config.Config{Options: opts, OutboundPort: "0"}

	conn := &pom_grpc.CachedOutboundGRPClientConn{}

	withGetter, err := New(ctx, DefaultPrefix, cfg, conn,
		WithAuthenticatorGetter(func(_ context.Context, _ string) (identity.Authenticator, error) {
			return &mockAuthenticator{}, nil
		}))
	require.NoError(t, err)
	assert.NotNil(t, withGetter.idpStore, "an authenticator getter must wire the shared store")

	withoutGetter, err := New(ctx, DefaultPrefix, cfg, conn)
	require.NoError(t, err)
	assert.Nil(t, withoutGetter.idpStore, "without a getter there is nothing to refresh with")
}

// TestRefreshGrantAnswersWithinTheGatewayBudget: a slow identity provider must
// not hold the request until the gateway in front of this route gives up, which
// would replace the endpoint's own 503 and Retry-After with a bodyless 504 the
// client cannot act on. Runs on real time, because the budget is real.
func TestRefreshGrantAnswersWithinTheGatewayBudget(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{TokenEndpointAuthMethod: new("none")},
	})
	require.NoError(t, err)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return &mockAuthenticator{
			refreshFunc: func(rctx context.Context, tok *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
				// Slower than the caller's budget, but not slower than the
				// detached attempt's own deadline.
				select {
				case <-release:
				case <-rctx.Done():
					return nil, rctx.Err()
				case <-time.After(30 * time.Second):
				}
				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: tok.RefreshToken,
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}, nil
	}
	srv := storeWiredHandler(storage, testCipher, getAuth)

	rec := &oauth21proto.MCPRefreshToken{
		Id:                   "slow-idp-refresh-token-id",
		UserId:               "slow-idp-user",
		ClientId:             clientID,
		IdpId:                "test-idp",
		UpstreamRefreshToken: "upstream-refresh-token",
		IssuedAt:             timestamppb.Now(),
		ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
	}
	require.NoError(t, storage.PutMCPRefreshToken(ctx, rec))
	refreshToken, err := srv.CreateRefreshToken(rec.Id, clientID, rec.ExpiresAt.AsTime())
	require.NoError(t, err)

	start := time.Now()
	res := postRefreshGrant(ctx, t, srv, clientID, refreshToken)
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusServiceUnavailable, res.Code,
		"a slow provider is a retry, not a refusal; body: %s", res.Body.String())
	assert.NotEmpty(t, res.Header().Get("Retry-After"))
	assert.Less(t, elapsed, 13*time.Second,
		"the grant must answer well inside the gateway's 15 second route timeout")
}

// TestAuthorizeRefusesAgainstADeadUpstreamSession: issuing a code while the
// canonical record is a tombstone would mint tokens the very next refresh grant
// refuses, so the client would authorize and be refused in turn until something
// else repaired the record. Refusing here sends the user through the sign-in
// that does repair it.
func TestAuthorizeRefusesAgainstADeadUpstreamSession(t *testing.T) {
	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)

	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	getAuth := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return &mockAuthenticator{
			refreshFunc: func(_ context.Context, tok *oauth2.Token, _ identitystate.State) (*oauth2.Token, error) {
				if tok.RefreshToken != "post-login-upstream-token" {
					return nil, &oauth2.RetrieveError{
						Response:  &http.Response{StatusCode: http.StatusBadRequest},
						ErrorCode: "invalid_grant",
					}
				}
				return &oauth2.Token{
					AccessToken:  "fresh-access-token",
					RefreshToken: tok.RefreshToken,
					Expiry:       time.Now().Add(time.Hour),
				}, nil
			},
		}, nil
	}
	srv := storeWiredHandler(storage, testCipher, getAuth)
	// The authorize endpoint resolves route info once past the gate.
	srv.hosts = NewHostInfo(&config.Config{Options: config.NewDefaultOptions()}, http.DefaultClient)

	const userID, idpID = "authorize-dead-user", "test-idp"
	testSession := session.Create(idpID, "authorize-dead-session", userID, time.Now(), 24*time.Hour)
	testSession.OauthToken = &session.OAuthToken{RefreshToken: "stale-upstream-token"}
	_, err = storage.PutSession(ctx, testSession)
	require.NoError(t, err)

	// Drive the canonical record to a tombstone.
	require.NoError(t, srv.idpStore.Register(ctx, userID, idpID, "stale-upstream-token"))
	_, err = srv.idpStore.EnsureLive(ctx, userID, idpID)
	require.ErrorIs(t, err, idpsession.ErrUpstreamSessionDead)

	dead, err := srv.idpStore.IsDeadHint(ctx, userID, idpID)
	require.NoError(t, err)
	require.True(t, dead)

	// Drive the endpoint, not just the helper: a gate nothing exercises can be
	// deleted without a test noticing.
	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{
			TokenEndpointAuthMethod: new("none"),
			RedirectUris:            []string{"http://localhost:8080/callback"},
		},
	})
	require.NoError(t, err)

	authorize := func(t *testing.T) *httptest.ResponseRecorder {
		t.Helper()
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://localhost:8080/callback"},
			"state":                 {"state-value"},
			"code_challenge":        {computeS256Challenge("test-code-verifier-that-is-long-enough-for-pkce")},
			"code_challenge_method": {"S256"},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/authorize?"+q.Encode(), nil)
		require.NoError(t, err)
		req.Header.Set(httputil.HeaderPomeriumJWTAssertion,
			makeTestJWT(t, testSession.Id, userID))
		w := httptest.NewRecorder()
		srv.Authorize(w, req)
		return w
	}

	res := authorize(t)
	require.Equal(t, http.StatusUnauthorized, res.Code,
		"a tombstone must not produce an authorization code; body: %s", res.Body.String())
	assert.Contains(t, res.Body.String(), "Sign in again",
		"the user is told what to do about it")

	// A login supersedes the record, and the same request now gets a code.
	require.NoError(t, srv.idpStore.Supersede(ctx, userID, idpID, "post-login-upstream-token", ""))
	assert.False(t, srv.upstreamSessionIsDead(ctx, testSession.Id, userID),
		"after a login the authorization proceeds")
	res = authorize(t)
	assert.Equal(t, http.StatusFound, res.Code,
		"after a login the authorization completes; body: %s", res.Body.String())
	assert.Contains(t, res.Header().Get("Location"), "code=",
		"and hands back an authorization code")

	// And the grant those tokens are for now works.
	rec := &oauth21proto.MCPRefreshToken{
		Id:                   "authorize-dead-refresh-token-id",
		UserId:               userID,
		ClientId:             "authorize-dead-client",
		IdpId:                idpID,
		UpstreamRefreshToken: "post-login-upstream-token",
		IssuedAt:             timestamppb.Now(),
		ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
	}
	require.NoError(t, storage.PutMCPRefreshToken(ctx, rec))
	_, _, err = srv.getOrRecreateSession(ctx, rec)
	assert.NoError(t, err, "refresh grants work again after the login")
}
