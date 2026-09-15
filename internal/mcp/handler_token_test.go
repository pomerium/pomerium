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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/opaquetoken"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	identitystate "github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

// setupTestDatabroker creates a test databroker server and returns a storage instance.
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
	return NewStorage(databroker_grpc.NewStaticClientGetter(client))
}

// putIDPSession seeds a centralized idpsession.IDPSession record (id == userID) directly
// via the databroker client, as production code does via idpsession.RevokeIDPSession /
// the identity-manager's centralized session sync.
func putIDPSession(ctx context.Context, t *testing.T, storage *Storage, idpSess *idpsession.IDPSession) {
	t.Helper()
	_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{
		Records: []*databroker_grpc.Record{databroker_grpc.NewRecord(idpSess)},
	})
	require.NoError(t, err)
}

// putBinding seeds an idpsession.Binding record directly, so tests can exercise binding
// states (revoked, or pointing at a session that was never actually stored) independently
// of the normal PutBoundSession path.
func putBinding(ctx context.Context, t *testing.T, storage *Storage, binding *idpsession.Binding) {
	t.Helper()
	_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{
		Records: []*databroker_grpc.Record{databroker_grpc.NewRecord(binding)},
	})
	require.NoError(t, err)
}

// validIDPSession builds a VALID idpsession.IDPSession fixture for userID/idpID with the
// given upstream oauth token and claims.
func validIDPSession(userID, idpID string, oauthToken *idpsession.OAuthToken, claims map[string]any) *idpsession.IDPSession {
	var claimsPB *structpb.Struct
	if claims != nil {
		var err error
		claimsPB, err = structpb.NewStruct(claims)
		if err != nil {
			panic(err)
		}
	}
	return &idpsession.IDPSession{
		Id:         userID,
		UserId:     userID,
		IdpId:      idpID,
		OauthToken: oauthToken,
		State: &idpsession.SessionState{
			State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID,
		},
		Claims: claimsPB,
	}
}

func computeS256Challenge(verifier string) string {
	sha256Hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha256Hash[:])
}

// newTestTokenHandler builds a Handler around storage for /token tests.
func newHandlerWithStorage(storage HandlerStorage, cipher cipher.AEAD, accessTokenTTL time.Duration) *Handler {
	return &Handler{
		cipher:         cipher,
		storage:        storage,
		accessTokenTTL: accessTokenTTL,
	}
}

// registerNoneAuthClient registers a public ("none" token-endpoint-auth-method) DCR client.
func registerNoneAuthClient(ctx context.Context, t *testing.T, storage *Storage) string {
	t.Helper()
	clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{
			TokenEndpointAuthMethod: new(rfc7591v1.TokenEndpointAuthMethodNone),
		},
	})
	require.NoError(t, err)
	return clientID
}

// sealAuthCode seeds an authorization request for userID bound to clientID with S256
// PKCE, and returns the sealed authorization code together with the code verifier to
// present at the token endpoint.
func sealAuthCode(ctx context.Context, t *testing.T, storage *Storage, cipher cipher.AEAD, clientID, userID string, scopes []string) (code, codeVerifier string) {
	t.Helper()

	codeVerifier = "test-code-verifier-that-is-long-enough-for-pkce"
	codeChallenge := computeS256Challenge(codeVerifier)

	authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
		ClientId:            clientID,
		UserId:              userID,
		CodeChallenge:       new(codeChallenge),
		CodeChallengeMethod: new("S256"),
		Scopes:              scopes,
	})
	require.NoError(t, err)

	code, err = opaquetoken.Seal(opaquetoken.TypeAuthorization, authReqID, time.Now().Add(time.Hour), clientID, cipher)
	require.NoError(t, err)
	return code, codeVerifier
}

// doTokenRequest POSTs form to the /token endpoint and returns the recorded response.
func doTokenRequest(srv *Handler, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Token(w, req)
	return w
}

// issueViaAuthCode drives a full authorization_code grant through the HTTP handler
// (seeding a VALID IDPSession, registering a client, and sealing an authorization code
// along the way) and returns the client id and the resulting access/refresh tokens, for
// tests that go on to exercise the refresh_token grant.
func issueViaAuthCode(ctx context.Context, t *testing.T, srv *Handler, storage *Storage, userID string) (clientID, accessToken, refreshToken string) {
	t.Helper()

	putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", &idpsession.OAuthToken{
		AccessToken: "idp-access-token",
	}, nil))
	clientID = registerNoneAuthClient(ctx, t, storage)
	code, codeVerifier := sealAuthCode(ctx, t, storage, srv.cipher, clientID, userID, nil)

	w := doTokenRequest(srv, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())

	var tokenResp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokenResp))
	accessToken, _ = tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)
	refreshToken, _ = tokenResp["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)
	return clientID, accessToken, refreshToken
}

// tokenTestStorage wraps a real Storage backed by an in-memory databroker so most
// HandlerStorage calls behave exactly as production storage does, while letting
// individual tests override specific methods (to inject storage errors, or synthesize a
// response) and count how many times PutBoundSession / PutSession were called.
type tokenTestStorage struct {
	*Storage

	getIDPSessionFunc   func(ctx context.Context, id string) (*idpsession.IDPSession, error)
	getBindingFunc      func(ctx context.Context, id string) (*idpsession.Binding, error)
	getSessionFunc      func(ctx context.Context, id string) (*session.Session, uint64, error)
	putBoundSessionFunc func(ctx context.Context, s *session.Session, details map[string]string) (uint64, error)
	putSessionFunc      func(ctx context.Context, s *session.Session) (uint64, error)

	mu                   sync.Mutex
	putBoundSessionCalls int
	putSessionCalls      int
}

func (s *tokenTestStorage) GetValidIDPSession(ctx context.Context, id string) (*idpsession.IDPSession, error) {
	if s.getIDPSessionFunc != nil {
		return s.getIDPSessionFunc(ctx, id)
	}
	return s.Storage.GetValidIDPSession(ctx, id)
}

func (s *tokenTestStorage) GetActiveBinding(ctx context.Context, id string) (*idpsession.Binding, error) {
	if s.getBindingFunc != nil {
		return s.getBindingFunc(ctx, id)
	}
	return s.Storage.GetActiveBinding(ctx, id)
}

func (s *tokenTestStorage) GetSession(ctx context.Context, id string) (*session.Session, uint64, error) {
	if s.getSessionFunc != nil {
		return s.getSessionFunc(ctx, id)
	}
	return s.Storage.GetSession(ctx, id)
}

func (s *tokenTestStorage) PutBoundSession(ctx context.Context, sess *session.Session, details map[string]string) (uint64, error) {
	s.mu.Lock()
	s.putBoundSessionCalls++
	s.mu.Unlock()
	if s.putBoundSessionFunc != nil {
		return s.putBoundSessionFunc(ctx, sess, details)
	}
	return s.Storage.PutBoundSession(ctx, sess, details)
}

func (s *tokenTestStorage) PutSession(ctx context.Context, sess *session.Session) (uint64, error) {
	s.mu.Lock()
	s.putSessionCalls++
	s.mu.Unlock()
	if s.putSessionFunc != nil {
		return s.putSessionFunc(ctx, sess)
	}
	return s.Storage.PutSession(ctx, sess)
}

func (s *tokenTestStorage) counts() (putBoundSessionCalls, putSessionCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putBoundSessionCalls, s.putSessionCalls
}

func TestCreateTokenResponse(t *testing.T) {
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	srv := &Handler{
		cipher:         testCipher,
		accessTokenTTL: time.Hour,
	}

	clientID := "test-client-id"
	now := time.Now()
	sess := &session.Session{
		Id:       "test-session-id",
		UserId:   "test-user-id",
		IssuedAt: timestamppb.New(now),
	}

	t.Run("creates token response with scopes", func(t *testing.T) {
		scopes := []string{"openid", "profile"}

		resp, err := srv.createTokenResponse(sess, 0, clientID, now, scopes)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		require.NotNil(t, resp.ExpiresIn)
		assert.Equal(t, int64(time.Hour.Seconds()), *resp.ExpiresIn)
		require.NotNil(t, resp.RefreshToken)
		assert.NotEmpty(t, *resp.RefreshToken)
		require.NotNil(t, resp.Scope)
		assert.Equal(t, "openid profile", *resp.Scope)
	})

	t.Run("creates token response without scopes", func(t *testing.T) {
		resp, err := srv.createTokenResponse(sess, 0, clientID, now, nil)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.NotNil(t, resp.ExpiresIn)
		assert.NotNil(t, resp.RefreshToken)
		assert.Nil(t, resp.Scope)
	})

	t.Run("access token decrypts to the session id and carries the record version", func(t *testing.T) {
		resp, err := srv.createTokenResponse(sess, 42, clientID, now, nil)
		require.NoError(t, err)

		id, version, err := srv.GetSessionAndVersionFromAccessToken(resp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, sess.Id, id)
		assert.Equal(t, uint64(42), version)
	})

	t.Run("refresh token decrypts to the session id and issued_at, bound to the client", func(t *testing.T) {
		resp, err := srv.createTokenResponse(sess, 0, clientID, now, nil)
		require.NoError(t, err)

		payload, err := srv.DecryptRefreshToken(*resp.RefreshToken, clientID)
		require.NoError(t, err)
		assert.Equal(t, sess.Id, payload.GetId())
		assert.True(t, payload.GetIssuedAt().AsTime().Equal(now))

		// Trying to decrypt with a different client ID should fail.
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

func TestAuthorizationCodeGrant(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		spy := &tokenTestStorage{Storage: storage}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		userID := "auth-code-happy-user"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", &idpsession.OAuthToken{
			AccessToken: "idp-access-token",
		}, nil))

		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, []string{"openid"})

		before := time.Now()
		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())

		putBoundCalls, putCalls := spy.counts()
		assert.Equal(t, 1, putBoundCalls, "exactly one PutBoundSession call")
		assert.Equal(t, 0, putCalls, "PutSession (refresh-only) must not be called on the auth-code path")

		var tokenResp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokenResp))

		accessToken, _ := tokenResp["access_token"].(string)
		require.NotEmpty(t, accessToken)
		refreshToken, _ := tokenResp["refresh_token"].(string)
		require.NotEmpty(t, refreshToken)
		assert.Equal(t, "openid", tokenResp["scope"])
		assert.Equal(t, float64(5*time.Minute/time.Second), tokenResp["expires_in"])

		sessionID, version, err := srv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)

		sess, storedVersion, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, storedVersion, version, "access token's record version must match the stored session")
		assert.Equal(t, userID, sess.GetUserId())
		assert.False(t, sess.GetRefreshDisabled())
		assert.WithinDuration(t, before.Add(RefreshTokenTTL), sess.GetExpiresAt().AsTime(), time.Minute)

		binding, err := storage.GetActiveBinding(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, binding.GetId(), "binding id must equal the session id")
		assert.Equal(t, userID, binding.GetIdpSessionId())
		assert.Equal(t, idpsession.BindingProtocol_BINDING_PROTOCOL_MCP, binding.GetProtocol())
		assert.Equal(t, clientID, binding.GetDetails()["mcp_client_id"])
		assert.NotEmpty(t, binding.GetDetails()["client-ip"])

		payload, err := srv.DecryptRefreshToken(refreshToken, clientID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, payload.GetId())
		assert.True(t, payload.GetIssuedAt().AsTime().Equal(sess.GetIssuedAt().AsTime()))
	})

	t.Run("missing IDPSession returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, "no-such-user", nil)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	t.Run("INVALID IDPSession returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "invalid-idp-session-user"
		idpSess := validIDPSession(userID, "test-idp", nil, nil)
		idpSess.State = &idpsession.SessionState{State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID}
		putIDPSession(ctx, t, storage, idpSess)

		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	t.Run("PutBoundSession error returns 500", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		spy := &tokenTestStorage{
			Storage: storage,
			putBoundSessionFunc: func(context.Context, *session.Session, map[string]string) (uint64, error) {
				return 0, errors.New("simulated storage failure")
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		userID := "put-bound-session-fail-user"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("PKCE mismatch returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "pkce-mismatch-user"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, _ := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {"this-verifier-does-not-match-the-stored-challenge"},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("client ID mismatch returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "client-id-mismatch-user"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		clientID := registerNoneAuthClient(ctx, t, storage)
		otherClientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		// The authorization code is AEAD-bound to the client that requested it; a
		// different client presenting it fails to even decrypt it.
		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {otherClientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("authorization code is one-time use", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "one-time-use-user"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		}

		w1 := doTokenRequest(srv, form)
		require.Equal(t, http.StatusOK, w1.Code, "response body: %s", w1.Body.String())

		w2 := doTokenRequest(srv, form)
		assert.Equal(t, http.StatusBadRequest, w2.Code, "the same authorization code must not be redeemable twice")
	})
}

func TestRefreshTokenGrant(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path rotates the access and refresh token", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		setupSrv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)
		userID := "refresh-happy-user"
		clientID, accessToken, refreshToken := issueViaAuthCode(ctx, t, setupSrv, storage, userID)

		sessionID, _, err := setupSrv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)
		origSess, _, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)

		spy := &tokenTestStorage{Storage: storage}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())

		putBoundCalls, putCalls := spy.counts()
		assert.Equal(t, 0, putBoundCalls, "refresh must never touch the Binding via PutBoundSession")
		assert.Equal(t, 1, putCalls, "refresh stores the re-issued session exactly once")

		var tokenResp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokenResp))
		newAccessToken, _ := tokenResp["access_token"].(string)
		require.NotEmpty(t, newAccessToken)
		newRefreshToken, _ := tokenResp["refresh_token"].(string)
		require.NotEmpty(t, newRefreshToken)
		assert.NotEqual(t, accessToken, newAccessToken)
		assert.NotEqual(t, refreshToken, newRefreshToken)
		_, hasScope := tokenResp["scope"]
		assert.False(t, hasScope, "the refresh response must omit scope (RFC 6749 §5.1)")

		newSessionID, _, err := srv.GetSessionAndVersionFromAccessToken(newAccessToken)
		require.NoError(t, err)
		assert.Equal(t, sessionID, newSessionID, "refresh re-issues the same session id")

		newSess, _, err := storage.GetSession(ctx, newSessionID)
		require.NoError(t, err)
		assert.True(t, newSess.GetExpiresAt().AsTime().After(origSess.GetExpiresAt().AsTime()),
			"session expiry should have slid forward")

		payload, err := srv.DecryptRefreshToken(newRefreshToken, clientID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, payload.GetId())
		assert.True(t, payload.GetIssuedAt().AsTime().Equal(newSess.GetIssuedAt().AsTime()))
	})

	t.Run("old refresh token replay after rotation returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "refresh-replay-user"
		clientID, _, refreshToken := issueViaAuthCode(ctx, t, srv, storage, userID)

		w1 := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		require.Equal(t, http.StatusOK, w1.Code, "response body: %s", w1.Body.String())

		// The original refresh token's issued_at no longer matches the (rotated)
		// session, so replaying it must fail.
		w2 := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w2.Code)
	})

	t.Run("revoked binding returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "revoked-binding-user"
		sessionID := "revoked-binding-session"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		putBinding(ctx, t, storage, idpsession.NewBinding(userID, idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
			&session.Session{Id: sessionID}, nil).Revoke())

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken(sessionID, clientID, time.Now().Add(RefreshTokenTTL), time.Now())
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing binding returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken("no-such-session", clientID, time.Now().Add(RefreshTokenTTL), time.Now())
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing IDPSession returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		sessionID := "no-idp-session-session"
		putBinding(ctx, t, storage, idpsession.NewBinding("no-such-user", idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
			&session.Session{Id: sessionID}, nil))

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken(sessionID, clientID, time.Now().Add(RefreshTokenTTL), time.Now())
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("INVALID IDPSession returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "invalid-idp-session-refresh-user"
		idpSess := validIDPSession(userID, "test-idp", nil, nil)
		idpSess.State = &idpsession.SessionState{State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID}
		putIDPSession(ctx, t, storage, idpSess)

		sessionID := "invalid-idp-session-session"
		putBinding(ctx, t, storage, idpsession.NewBinding(userID, idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
			&session.Session{Id: sessionID}, nil))

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken(sessionID, clientID, time.Now().Add(RefreshTokenTTL), time.Now())
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing session returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "missing-session-user"
		putIDPSession(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))

		sessionID := "missing-session-session"
		putBinding(ctx, t, storage, idpsession.NewBinding(userID, idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
			&session.Session{Id: sessionID}, nil))

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken(sessionID, clientID, time.Now().Add(RefreshTokenTTL), time.Now())
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("wrong client_id fails", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "wrong-client-id-user"
		_, _, refreshToken := issueViaAuthCode(ctx, t, srv, storage, userID)
		otherClientID := registerNoneAuthClient(ctx, t, storage)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {otherClientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("expired refresh token fails", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken("expired-refresh-token-session", clientID,
			time.Now().Add(-time.Hour), time.Now().Add(-2*time.Hour))
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("non-NotFound storage error on GetBinding returns 500", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		spy := &tokenTestStorage{
			Storage: storage,
			getBindingFunc: func(context.Context, string) (*idpsession.Binding, error) {
				return nil, status.Error(codes.Internal, "simulated storage failure")
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		clientID := registerNoneAuthClient(ctx, t, storage)
		refreshToken, err := srv.CreateRefreshToken("some-session-id", clientID, time.Now().Add(RefreshTokenTTL), time.Now())
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("concurrent refresh token usage", func(t *testing.T) {
		// N goroutines present the same refresh token concurrently. refreshMCPSession
		// reads the session's issued_at, compares it to the presented token's, and only
		// then writes a re-issued session: nothing serializes the read against another
		// goroutine's write, so every goroutine can observe the same (pre-rotation)
		// issued_at and succeed, each rotating the session to its own new issued_at.
		// Whichever write physically lands last is what's now durably stored, so on a
		// second pass exactly one of the returned refresh tokens — the one whose
		// issued_at matches that final generation — should still work.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "concurrent-refresh-user"
		clientID, _, refreshToken := issueViaAuthCode(ctx, t, srv, storage, userID)

		const n = 10
		statusCodes := make([]int, n)
		newRefreshTokens := make([]string, n)

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start

				w := doTokenRequest(srv, url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {refreshToken},
					"client_id":     {clientID},
				})
				statusCodes[i] = w.Code
				if w.Code == http.StatusOK {
					var resp map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil {
						newRefreshTokens[i], _ = resp["refresh_token"].(string)
					}
				}
			}(i)
		}
		close(start)
		wg.Wait()

		successCount := 0
		for i, code := range statusCodes {
			switch code {
			case http.StatusOK:
				successCount++
				assert.NotEmpty(t, newRefreshTokens[i])
			case http.StatusBadRequest:
				// expected for a losing concurrent attempt (rare, but possible if the
				// scheduler serializes some of the goroutines before they all read).
			default:
				t.Errorf("unexpected status code: %d", code)
			}
		}
		require.GreaterOrEqual(t, successCount, 1, "at least one concurrent refresh should succeed")
		t.Logf("concurrent refresh: %d/%d succeeded", successCount, n)

		// Replay every token that came back, one at a time: exactly one — the one whose
		// issued_at matches whatever generation is now durably stored — must still work.
		secondSuccesses := 0
		for i, code := range statusCodes {
			if code != http.StatusOK {
				continue
			}
			w := doTokenRequest(srv, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {newRefreshTokens[i]},
				"client_id":     {clientID},
			})
			if w.Code == http.StatusOK {
				secondSuccesses++
			} else {
				assert.Equal(t, http.StatusBadRequest, w.Code)
			}
		}
		assert.Equal(t, 1, secondSuccesses, "exactly one refresh token should still be valid on a second use")
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
