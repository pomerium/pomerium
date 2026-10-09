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
	"sync/atomic"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
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

// testIDPSessionID is the id of the centralized IdP session the tests sign userID
// into. It differs from the user id, as it does in production.
func testIDPSessionID(userID string) string { return "idp-session-" + userID }

// testBrowserSessionID is the id of the browser session that consents at /authorize
// on userID's behalf.
func testBrowserSessionID(userID string) string { return "browser-session-" + userID }

// signIn seeds what a browser sign-in leaves behind: the centralized IDPSession,
// a live browser session, and that session's Binding to the IDPSession, which
// the auth-code exchange resolves the IDPSession through.
func signIn(ctx context.Context, t *testing.T, storage *Storage, idpSess *idpsession.IDPSession) {
	t.Helper()
	now := time.Now()
	browser := &session.Session{
		Id:        testBrowserSessionID(idpSess.GetUserId()),
		UserId:    idpSess.GetUserId(),
		IdpId:     idpSess.GetIdpId(),
		IssuedAt:  timestamppb.New(now),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
	_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{
		Records: append([]*databroker_grpc.Record{databroker_grpc.NewRecord(idpSess)},
			idpsession.NewBoundRecords(idpSess.GetId(), idpSess.GetUserId(),
				idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil, browser)...),
	})
	require.NoError(t, err)
}

// putBinding seeds an idpsession.Binding record directly, so tests can exercise
// bindings (deleted, or pointing at a session that was never actually stored)
// independently of the normal PutBoundSession path.
func putBinding(ctx context.Context, t *testing.T, storage *Storage, binding *idpsession.Binding) {
	t.Helper()
	_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{
		Records: []*databroker_grpc.Record{databroker_grpc.NewRecord(binding)},
	})
	require.NoError(t, err)
}

// propagateToSession does to a bound session what the identity manager's
// reconciler does whenever the IdP session it is bound to changes: it patches the
// IdP-derived fields in place. That bumps the session's record version and leaves
// its issued_at alone.
func propagateToSession(ctx context.Context, t *testing.T, storage *Storage, sessionID, idpAccessToken string) {
	t.Helper()
	patch := &session.Session{Id: sessionID, OauthToken: &session.OAuthToken{AccessToken: idpAccessToken}}
	mask, err := fieldmaskpb.New(patch, "oauth_token")
	require.NoError(t, err)
	_, err = session.Patch(ctx, storage.client(), patch, mask)
	require.NoError(t, err)
}

// validIDPSession builds an idpsession.IDPSession fixture for userID/idpID with the
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
		Id:         testIDPSessionID(userID),
		UserId:     userID,
		IdpId:      idpID,
		OauthToken: oauthToken,
		Claims:     claimsPB,
	}
}

func computeS256Challenge(verifier string) string {
	sha256Hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha256Hash[:])
}

// newHandlerWithStorage builds a Handler around storage for /token tests.
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

// sealAuthCode seeds an authorization request for userID, consented to from
// userID's browser session, bound to clientID with S256 PKCE, and returns the
// sealed authorization code together with the code verifier to present at the
// token endpoint.
func sealAuthCode(ctx context.Context, t *testing.T, storage *Storage, cipher cipher.AEAD, clientID, userID string, scopes []string) (code, codeVerifier string) {
	t.Helper()

	codeVerifier = "test-code-verifier-that-is-long-enough-for-pkce"
	codeChallenge := computeS256Challenge(codeVerifier)

	authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
		ClientId:            clientID,
		SessionId:           testBrowserSessionID(userID),
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
// (signing the user in, registering a client, and sealing an authorization code
// along the way) and returns the client id and the resulting access/refresh tokens, for
// tests that go on to exercise the refresh_token grant.
func issueViaAuthCode(ctx context.Context, t *testing.T, srv *Handler, storage *Storage, userID string) (clientID, accessToken, refreshToken string) {
	t.Helper()

	signIn(ctx, t, storage, validIDPSession(userID, "test-idp", &idpsession.OAuthToken{
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
	putBoundSessionFunc func(ctx context.Context, s *session.Session, idpSessionID string, details map[string]string) (uint64, error)
	putSessionFunc      func(ctx context.Context, s *session.Session, version uint64) (uint64, error)

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

func (s *tokenTestStorage) PutBoundSession(ctx context.Context, sess *session.Session, idpSessionID string, details map[string]string) (uint64, error) {
	s.mu.Lock()
	s.putBoundSessionCalls++
	s.mu.Unlock()
	if s.putBoundSessionFunc != nil {
		return s.putBoundSessionFunc(ctx, sess, idpSessionID, details)
	}
	return s.Storage.PutBoundSession(ctx, sess, idpSessionID, details)
}

func (s *tokenTestStorage) PutSession(ctx context.Context, sess *session.Session, version uint64) (uint64, error) {
	s.mu.Lock()
	s.putSessionCalls++
	s.mu.Unlock()
	if s.putSessionFunc != nil {
		return s.putSessionFunc(ctx, sess, version)
	}
	return s.Storage.PutSession(ctx, sess, version)
}

func (s *tokenTestStorage) counts() (putBoundSessionCalls, putSessionCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putBoundSessionCalls, s.putSessionCalls
}

// authReqBarrierStorage holds every authorization-code exchange at its read of
// the authorization request until n of them have read it, so that all of them
// go on to redeem a code each saw as unredeemed.
type authReqBarrierStorage struct {
	*tokenTestStorage
	n       int32
	reads   atomic.Int32
	allRead chan struct{}
}

func (s *authReqBarrierStorage) GetAuthorizationRequest(ctx context.Context, id string) (*oauth21proto.AuthorizationRequest, uint64, error) {
	req, version, err := s.Storage.GetAuthorizationRequest(ctx, id)
	if s.reads.Add(1) == s.n {
		close(s.allRead)
	}
	<-s.allRead
	return req, version, err
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

		resp, err := srv.createTokenResponse(sess, 0, clientID, scopes)
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
		resp, err := srv.createTokenResponse(sess, 0, clientID, nil)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.NotNil(t, resp.ExpiresIn)
		assert.NotNil(t, resp.RefreshToken)
		assert.Nil(t, resp.Scope)
	})

	t.Run("access token decrypts to the session id and carries the record version", func(t *testing.T) {
		resp, err := srv.createTokenResponse(sess, 42, clientID, nil)
		require.NoError(t, err)

		id, version, err := srv.GetSessionAndVersionFromAccessToken(resp.AccessToken)
		require.NoError(t, err)
		assert.Equal(t, sess.Id, id)
		assert.Equal(t, uint64(42), version)
	})

	t.Run("refresh token decrypts to the session id and issued_at, bound to the client", func(t *testing.T) {
		resp, err := srv.createTokenResponse(sess, 0, clientID, nil)
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
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", &idpsession.OAuthToken{
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
		assert.Equal(t, testIDPSessionID(userID), binding.GetIdpSessionId(),
			"the MCP session must be bound to the IDPSession the consenting browser session is bound to")
		assert.Equal(t, userID, binding.GetUserId())
		assert.Equal(t, idpsession.BindingProtocol_BINDING_PROTOCOL_MCP, binding.GetProtocol())
		assert.Equal(t, clientID, binding.GetDetails()["mcp_client_id"])
		assert.NotEmpty(t, binding.GetDetails()["client-ip"])

		payload, err := srv.DecryptRefreshToken(refreshToken, clientID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, payload.GetId())
		assert.True(t, payload.GetIssuedAt().AsTime().Equal(sess.GetIssuedAt().AsTime()))
	})

	t.Run("signed-out browser session returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		// No browser binding: the consenting browser session signed out before the
		// code was redeemed.
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

	t.Run("browser session that expired after consent returns invalid_grant", func(t *testing.T) {
		// The binding outlives the session until the identity manager reaps
		// it; in that window the code must not mint a year-long grant from a
		// consent whose session is no longer valid.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "expired-browser-user"
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		_, err = session.Put(ctx, storage.client(), session.Create("test-idp", testBrowserSessionID(userID), userID,
			time.Now().Add(-2*time.Hour), time.Hour))
		require.NoError(t, err)
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	t.Run("browser session deleted before redemption returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "deleted-browser-user"
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		err = session.Delete(ctx, storage.client(), testBrowserSessionID(userID))
		require.NoError(t, err)
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	t.Run("missing IDPSession returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		// The browser binding is still there but its IDPSession is gone: the
		// identity manager has not reaped the binding yet.
		userID := "missing-idp-session-user"
		putBinding(ctx, t, storage, idpsession.NewBinding(testIDPSessionID(userID), userID,
			idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
			&session.Session{Id: testBrowserSessionID(userID)}, nil))

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

	t.Run("browser session bound to another user returns invalid_grant", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID, otherUserID := "consenting-user", "other-user"
		signIn(ctx, t, storage, validIDPSession(otherUserID, "test-idp", nil, nil))
		putBinding(ctx, t, storage, idpsession.NewBinding(testIDPSessionID(otherUserID), otherUserID,
			idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
			&session.Session{Id: testBrowserSessionID(userID)}, nil))

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
			putBoundSessionFunc: func(context.Context, *session.Session, string, map[string]string) (uint64, error) {
				return 0, errors.New("simulated storage failure")
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		userID := "put-bound-session-fail-user"
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
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
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
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
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
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
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
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

	t.Run("concurrent redemption of one code issues one grant", func(t *testing.T) {
		// Every request is held after reading the authorization request until
		// all of them have read it, so each sees the code as unredeemed.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		userID := "concurrent-code-user"
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		const n = 3
		spy := &authReqBarrierStorage{
			tokenTestStorage: &tokenTestStorage{Storage: storage},
			n:                n,
			allRead:          make(chan struct{}),
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		}
		results := make(chan *httptest.ResponseRecorder, n)
		for range n {
			go func() { results <- doTokenRequest(srv, form) }()
		}
		successes := 0
		for range n {
			w := <-results
			if w.Code == http.StatusOK {
				successes++
				continue
			}
			assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), "invalid_grant")
		}
		assert.Equal(t, 1, successes, "an authorization code must be redeemed at most once")
		putBound, _ := spy.counts()
		assert.Equal(t, 1, putBound, "each redemption minted its own bound MCP session")
	})

	t.Run("consent recorded from an MCP client session is refused", func(t *testing.T) {
		// /authorize under the MCP prefix accepts an MCP access token as the caller's
		// identity, so an MCP client can reach it without a browser and get a code
		// whose session_id is its own MCP session. Redeeming that would mint a second,
		// independently revocable grant with nobody consenting: only a browser
		// session's consent may be redeemed.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "mcp-consent-user"
		_, accessToken, _ := issueViaAuthCode(ctx, t, srv, storage, userID)
		mcpSessionID, _, err := srv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)

		otherClientID := registerNoneAuthClient(ctx, t, storage)
		codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce"
		authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
			ClientId:            otherClientID,
			SessionId:           mcpSessionID,
			UserId:              userID,
			CodeChallenge:       new(computeS256Challenge(codeVerifier)),
			CodeChallengeMethod: new("S256"),
		})
		require.NoError(t, err)
		code, err := opaquetoken.Seal(opaquetoken.TypeAuthorization, authReqID, time.Now().Add(time.Hour), otherClientID, testCipher)
		require.NoError(t, err)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {otherClientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	t.Run("sign-out during the exchange leaves no live MCP session", func(t *testing.T) {
		// The user signs out after the exchange resolved their IdP session but before
		// the MCP session is written. Sign-out deletes the IdP session, and the
		// identity manager deletes the bindings it knows about, which cannot include
		// one written afterwards; it never deletes a binding whose IdP session is
		// already gone. The exchange must refuse, and leave nothing behind.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		userID := "sign-out-race-user"
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		clientID := registerNoneAuthClient(ctx, t, storage)
		code, codeVerifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		var boundSessionID string
		spy := &tokenTestStorage{
			Storage: storage,
			putBoundSessionFunc: func(ctx context.Context, s *session.Session, idpSessionID string, details map[string]string) (uint64, error) {
				signedOut := databroker_grpc.NewRecord(&idpsession.IDPSession{Id: idpSessionID})
				signedOut.DeletedAt = timestamppb.Now()
				_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{signedOut}})
				require.NoError(t, err)
				boundSessionID = s.GetId()
				return storage.PutBoundSession(ctx, s, idpSessionID, details)
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")

		require.NotEmpty(t, boundSessionID)
		_, _, err = storage.GetSession(ctx, boundSessionID)
		assert.Equal(t, codes.NotFound, status.Code(err), "the MCP session outlived the sign-out")
		_, err = storage.GetActiveBinding(ctx, boundSessionID)
		assert.Equal(t, codes.NotFound, status.Code(err), "the MCP binding outlived the sign-out")
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
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
		binding := idpsession.NewBinding(testIDPSessionID(userID), userID, idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
			&session.Session{Id: sessionID}, nil)
		putBinding(ctx, t, storage, binding)
		// Revoking a binding deletes it.
		revoked := databroker_grpc.NewRecord(binding)
		revoked.DeletedAt = timestamppb.Now()
		_, err = storage.client().Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{revoked}})
		require.NoError(t, err)

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
		putBinding(ctx, t, storage, idpsession.NewBinding(testIDPSessionID("no-such-user"), "no-such-user",
			idpsession.BindingProtocol_BINDING_PROTOCOL_MCP, &session.Session{Id: sessionID}, nil))

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
		signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))

		sessionID := "missing-session-session"
		putBinding(ctx, t, storage, idpsession.NewBinding(testIDPSessionID(userID), userID,
			idpsession.BindingProtocol_BINDING_PROTOCOL_MCP, &session.Session{Id: sessionID}, nil))

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

	t.Run("concurrent refresh is single use", func(t *testing.T) {
		// N goroutines present the same refresh token at once. A barrier in GetSession
		// holds every request until all of them have read the pre-rotation session, so
		// all of them pass the issued_at check. The conditional write must then let
		// exactly one of them rotate the session; the others are told the token is gone.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		clientID, _, refreshToken := issueViaAuthCode(ctx, t,
			newHandlerWithStorage(storage, testCipher, 5*time.Minute), storage, "concurrent-refresh-user")

		const n = 4
		allRead := make(chan struct{})
		var reads atomic.Int32
		spy := &tokenTestStorage{
			Storage: storage,
			getSessionFunc: func(ctx context.Context, id string) (*session.Session, uint64, error) {
				sess, version, err := storage.GetSession(ctx, id)
				if reads.Add(1) == n {
					close(allRead)
				}
				<-allRead
				return sess, version, err
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		refresh := func(token string) *httptest.ResponseRecorder {
			return doTokenRequest(srv, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {token},
				"client_id":     {clientID},
			})
		}

		results := make(chan *httptest.ResponseRecorder, n)
		for range n {
			go func() { results <- refresh(refreshToken) }()
		}
		var winners []string
		for range n {
			w := <-results
			switch w.Code {
			case http.StatusOK:
				var resp map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				winners = append(winners, resp["refresh_token"].(string))
			case http.StatusBadRequest:
				assert.Contains(t, w.Body.String(), "invalid_grant")
			default:
				t.Errorf("unexpected status code %d: %s", w.Code, w.Body.String())
			}
		}
		require.Len(t, winners, 1, "a refresh token must be consumed exactly once")

		// The winner holds the live generation.
		assert.Equal(t, http.StatusOK, refresh(winners[0]).Code)
	})

	t.Run("identity manager propagation during a refresh does not consume the token", func(t *testing.T) {
		// The identity manager re-applies the IdP session to every session bound to
		// it whenever the IdP session changes: right after a consent binds a new MCP
		// session, on every background IdP token refresh, on every userinfo update.
		// Landing between the refresh's read of the session and its conditional
		// write, that rewrite does not rotate issued_at: the refresh token is still
		// the live generation and must be honored.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		clientID, _, refreshToken := issueViaAuthCode(ctx, t,
			newHandlerWithStorage(storage, testCipher, 5*time.Minute), storage, "propagation-race-user")

		var once sync.Once
		spy := &tokenTestStorage{
			Storage: storage,
			getSessionFunc: func(ctx context.Context, id string) (*session.Session, uint64, error) {
				sess, version, err := storage.GetSession(ctx, id)
				once.Do(func() { propagateToSession(ctx, t, storage, id, "refreshed-idp-access-token") })
				return sess, version, err
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	})

	t.Run("a refresh does not roll back tokens the identity manager propagated", func(t *testing.T) {
		// The identity manager refreshes the IdP session and propagates the new
		// upstream tokens to the MCP session while a refresh is in flight, after the
		// refresh has read the IdP session. The refresh must not write the IdP
		// session it read back over them.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		setupSrv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "propagation-rollback-user"
		clientID, accessToken, refreshToken := issueViaAuthCode(ctx, t, setupSrv, storage, userID)
		sessionID, _, err := setupSrv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)

		var once sync.Once
		spy := &tokenTestStorage{
			Storage: storage,
			getIDPSessionFunc: func(ctx context.Context, id string) (*idpsession.IDPSession, error) {
				read, err := storage.GetValidIDPSession(ctx, id)
				once.Do(func() {
					refreshed := validIDPSession(userID, "test-idp", &idpsession.OAuthToken{
						AccessToken: "refreshed-idp-access-token",
					}, nil)
					_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{
						Records: []*databroker_grpc.Record{databroker_grpc.NewRecord(refreshed)},
					})
					require.NoError(t, err)
					propagateToSession(ctx, t, storage, sessionID, "refreshed-idp-access-token")
				})
				return read, err
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())

		sess, _, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, "refreshed-idp-access-token", sess.GetOauthToken().GetAccessToken(),
			"the refresh wrote an older IdP session over the propagated one")
	})

	t.Run("a session rewritten on every attempt fails the refresh without consuming the token", func(t *testing.T) {
		// Retrying is bounded. Running out of attempts is a server-side condition:
		// the token was never consumed, so the client must not be told to discard it.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		clientID, _, refreshToken := issueViaAuthCode(ctx, t,
			newHandlerWithStorage(storage, testCipher, 5*time.Minute), storage, "propagation-storm-user")

		spy := &tokenTestStorage{
			Storage: storage,
			getSessionFunc: func(ctx context.Context, id string) (*session.Session, uint64, error) {
				sess, version, err := storage.GetSession(ctx, id)
				propagateToSession(ctx, t, storage, id, "refreshed-idp-access-token")
				return sess, version, err
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}
		w := doTokenRequest(srv, form)
		assert.Equal(t, http.StatusInternalServerError, w.Code, "response body: %s", w.Body.String())
		_, putCalls := spy.counts()
		assert.Equal(t, refreshWriteAttempts, putCalls)

		w = doTokenRequest(newHandlerWithStorage(storage, testCipher, 5*time.Minute), form)
		assert.Equal(t, http.StatusOK, w.Code, "the token must still be good: %s", w.Body.String())
	})

	t.Run("a write whose reply was lost still hands out the rotated token", func(t *testing.T) {
		// A conditional write can commit while its reply is lost (a deadline, a
		// forwarded call whose connection dropped). The stored issued_at has then
		// moved on, so the token the client holds is already dead. Answering with
		// a server error, which tells the client its token is still good, makes
		// the client's retry fail with invalid_grant and forces a re-consent. The
		// refresh must notice that its write landed and answer with the tokens.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		clientID, _, refreshToken := issueViaAuthCode(ctx, t,
			newHandlerWithStorage(storage, testCipher, 5*time.Minute), storage, "lost-reply-user")

		spy := &tokenTestStorage{
			Storage: storage,
			putSessionFunc: func(ctx context.Context, s *session.Session, version uint64) (uint64, error) {
				if _, err := storage.PutSession(ctx, s, version); err != nil {
					return 0, err
				}
				return 0, status.Error(codes.Unavailable, "transport is closing")
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		// The tokens describe the session as stored: the access token carries
		// the stored record version and the refresh token is the live generation.
		accessToken, _ := resp["access_token"].(string)
		sessionID, tokenVersion, err := srv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)
		_, storedVersion, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, storedVersion, tokenVersion)

		rotated, _ := resp["refresh_token"].(string)
		w = doTokenRequest(newHandlerWithStorage(storage, testCipher, 5*time.Minute), url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rotated},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusOK, w.Code, "the rotated token must be live: %s", w.Body.String())
	})

	t.Run("revocation while a refresh retries is not undone", func(t *testing.T) {
		// A rewrite forces a retry, and the MCP client is revoked before the retry
		// reads the session again: revoking deletes the binding and the identity
		// manager then deletes the session. The retry must not write it back.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		setupSrv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)
		clientID, accessToken, refreshToken := issueViaAuthCode(ctx, t, setupSrv, storage, "revoked-mid-retry-user")
		sessionID, _, err := setupSrv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)

		var reads atomic.Int32
		spy := &tokenTestStorage{
			Storage: storage,
			getSessionFunc: func(ctx context.Context, id string) (*session.Session, uint64, error) {
				switch reads.Add(1) {
				case 1:
					sess, version, err := storage.GetSession(ctx, id)
					propagateToSession(ctx, t, storage, id, "refreshed-idp-access-token")
					return sess, version, err
				case 2:
					var revoked []*databroker_grpc.Record
					for _, msg := range []interface {
						proto.Message
						GetId() string
					}{&idpsession.Binding{Id: id}, &session.Session{Id: id}} {
						record := databroker_grpc.NewRecord(msg)
						record.DeletedAt = timestamppb.Now()
						revoked = append(revoked, record)
					}
					_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{Records: revoked})
					require.NoError(t, err)
				}
				return storage.GetSession(ctx, id)
			},
		}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		w := doTokenRequest(srv, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
		_, _, err = storage.GetSession(ctx, sessionID)
		assert.Equal(t, codes.NotFound, status.Code(err), "the revoked session was written back")
	})
}
