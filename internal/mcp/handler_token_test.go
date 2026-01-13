package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
