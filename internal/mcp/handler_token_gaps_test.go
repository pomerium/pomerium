package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/opaquetoken"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// refreshForm is the form of a refresh_token grant request.
func refreshForm(clientID, refreshToken string) url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
}

// decodeTokenResponse decodes a successful /token response body.
func decodeTokenResponse(t *testing.T, w *httptest.ResponseRecorder) (accessToken, refreshToken string) {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, "response body: %s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	accessToken, _ = resp["access_token"].(string)
	refreshToken, _ = resp["refresh_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	return accessToken, refreshToken
}

// openAccessToken opens an access token minted by srv and returns its payload.
func openAccessToken(t *testing.T, srv *Handler, accessToken string) *opaquetoken.Payload {
	t.Helper()
	payload, err := opaquetoken.Open(opaquetoken.TypeAccess,
		strings.TrimPrefix(accessToken, accessTokenPrefix), srv.cipher, "", time.Now())
	require.NoError(t, err)
	return payload
}

func TestRefreshTokenGrantGaps(t *testing.T) {
	ctx := context.Background()

	newEnv := func(t *testing.T, userID string) (storage *Storage, srv *Handler, clientID, accessToken, refreshToken, sessionID string) {
		t.Helper()
		storage = setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv = newHandlerWithStorage(storage, testCipher, 5*time.Minute)
		clientID, accessToken, refreshToken = issueViaAuthCode(ctx, t, srv, storage, userID)
		sessionID, _, err = srv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)
		return storage, srv, clientID, accessToken, refreshToken, sessionID
	}

	t.Run("a refresh token with no issued_at is refused even when its id names a live session", func(t *testing.T) {
		// Refresh tokens minted before issued_at existed carry none. Unset must
		// never compare as a match: only the generation check stops a replayed
		// or forged-by-format token that names a live session.
		storage, srv, clientID, _, _, sessionID := newEnv(t, "no-issued-at-user")

		bare, err := opaquetoken.Seal(opaquetoken.TypeRefresh, sessionID, time.Now().Add(time.Hour), clientID, srv.cipher)
		require.NoError(t, err)

		w := doTokenRequest(srv, refreshForm(clientID, refreshTokenPrefix+bare))
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")

		_, _, err = storage.GetSession(ctx, sessionID)
		require.NoError(t, err, "a refused refresh must not touch the session")
	})

	t.Run("the refreshed access token references the session's new record version", func(t *testing.T) {
		// The access token's record version is a read-your-writes hint for the
		// authorize service. After a refresh it must name the version the refresh
		// wrote, not the pre-refresh version or zero.
		storage, srv, clientID, accessToken, refreshToken, sessionID := newEnv(t, "refresh-version-user")
		_, oldVersion, err := srv.GetSessionAndVersionFromAccessToken(accessToken)
		require.NoError(t, err)

		newAccessToken, _ := decodeTokenResponse(t, doTokenRequest(srv, refreshForm(clientID, refreshToken)))

		id, version, err := srv.GetSessionAndVersionFromAccessToken(newAccessToken)
		require.NoError(t, err)
		assert.Equal(t, sessionID, id)
		_, storedVersion, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, storedVersion, version, "access token must reference the version the refresh wrote")
		assert.Greater(t, version, oldVersion)
	})

	t.Run("access tokens expire after accessTokenTTL, independent of the 365d session", func(t *testing.T) {
		storage, srv, clientID, accessToken, refreshToken, sessionID := newEnv(t, "access-ttl-user")

		sess, _, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		payload := openAccessToken(t, srv, accessToken)
		assert.WithinDuration(t, time.Now().Add(5*time.Minute), payload.GetExpiresAt().AsTime(), 30*time.Second,
			"auth-code access token must carry accessTokenTTL")
		assert.True(t, payload.GetExpiresAt().AsTime().Before(sess.GetExpiresAt().AsTime()))

		before := time.Now()
		newAccessToken, _ := decodeTokenResponse(t, doTokenRequest(srv, refreshForm(clientID, refreshToken)))
		payload = openAccessToken(t, srv, newAccessToken)
		assert.WithinDuration(t, before.Add(5*time.Minute), payload.GetExpiresAt().AsTime(), 30*time.Second,
			"refreshed access token must carry accessTokenTTL")

		sess, _, err = storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		assert.WithinDuration(t, before.Add(RefreshTokenTTL), sess.GetExpiresAt().AsTime(), 30*time.Second,
			"refresh slides the session expiry to now + RefreshTokenTTL")
	})

	t.Run("after a concurrent race only the winner's refresh token is live", func(t *testing.T) {
		// Same barrier as "concurrent refresh is single use", additionally checking
		// that the token every racer presented is dead afterwards and that the
		// winner's access token names the stored version.
		storage, setupSrv, clientID, _, refreshToken, sessionID := newEnv(t, "race-generation-user")

		const n = 8
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
		srv := newHandlerWithStorage(spy, setupSrv.cipher, 5*time.Minute)

		results := make(chan *httptest.ResponseRecorder, n)
		for range n {
			go func() { results <- doTokenRequest(srv, refreshForm(clientID, refreshToken)) }()
		}
		var winnerAccess, winnerRefresh string
		var wins, losses int
		for range n {
			w := <-results
			switch w.Code {
			case http.StatusOK:
				wins++
				winnerAccess, winnerRefresh = decodeTokenResponse(t, w)
			case http.StatusBadRequest:
				losses++
				assert.Contains(t, w.Body.String(), "invalid_grant")
			default:
				t.Errorf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
		require.Equal(t, 1, wins)
		require.Equal(t, n-1, losses)

		_, version, err := srv.GetSessionAndVersionFromAccessToken(winnerAccess)
		require.NoError(t, err)
		_, storedVersion, err := storage.GetSession(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, storedVersion, version)

		plain := newHandlerWithStorage(storage, setupSrv.cipher, 5*time.Minute)
		w := doTokenRequest(plain, refreshForm(clientID, refreshToken))
		assert.Equal(t, http.StatusBadRequest, w.Code, "the raced token must be dead: %s", w.Body.String())
		decodeTokenResponse(t, doTokenRequest(plain, refreshForm(clientID, winnerRefresh)))
	})

	t.Run("revocation between the session read and the conditional write is not undone", func(t *testing.T) {
		// The revoke lands after the refresh read the session (version v) and before
		// it writes: the conditional write at v must be refused, and the retry must
		// see the session gone. On a backend whose conditional write re-creates a
		// deleted record, the revoked session would be written back.
		storage, setupSrv, clientID, _, refreshToken, sessionID := newEnv(t, "revoke-before-write-user")

		var revoked atomic.Bool
		spy := &tokenTestStorage{
			Storage: storage,
			getIDPSessionFunc: func(ctx context.Context, id string) (*idpsession.IDPSession, error) {
				if revoked.CompareAndSwap(false, true) {
					var records []*databroker_grpc.Record
					for _, msg := range []interface {
						proto.Message
						GetId() string
					}{&idpsession.Binding{Id: sessionID}, &session.Session{Id: sessionID}} {
						r := databroker_grpc.NewRecord(msg)
						r.DeletedAt = timestamppb.Now()
						records = append(records, r)
					}
					_, err := storage.client().Put(ctx, &databroker_grpc.PutRequest{Records: records})
					require.NoError(t, err)
				}
				return storage.GetValidIDPSession(ctx, id)
			},
		}
		srv := newHandlerWithStorage(spy, setupSrv.cipher, 5*time.Minute)

		w := doTokenRequest(srv, refreshForm(clientID, refreshToken))
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
		_, _, err := storage.GetSession(ctx, sessionID)
		assert.Equal(t, codes.NotFound, status.Code(err), "the revoked session was written back")
	})

	// A transient storage failure is not a dead grant: answering it with
	// invalid_grant tells the MCP client to discard its refresh token and send the
	// user through consent again.
	for _, tc := range []struct {
		name string
		spy  func(*Storage) *tokenTestStorage
		// wantPutCalls is how many PutSession calls the failure allows.
		wantPutCalls int
	}{
		{
			name: "GetSession unavailable",
			spy: func(s *Storage) *tokenTestStorage {
				return &tokenTestStorage{Storage: s, getSessionFunc: func(context.Context, string) (*session.Session, uint64, error) {
					return nil, 0, status.Error(codes.Unavailable, "databroker unavailable")
				}}
			},
		},
		{
			name: "GetValidIDPSession unavailable",
			spy: func(s *Storage) *tokenTestStorage {
				return &tokenTestStorage{Storage: s, getIDPSessionFunc: func(context.Context, string) (*idpsession.IDPSession, error) {
					return nil, status.Error(codes.Unavailable, "databroker unavailable")
				}}
			},
		},
		{
			name: "PutSession unavailable is not retried",
			spy: func(s *Storage) *tokenTestStorage {
				return &tokenTestStorage{Storage: s, putSessionFunc: func(context.Context, *session.Session, uint64) (uint64, error) {
					return 0, status.Error(codes.Unavailable, "databroker unavailable")
				}}
			},
			wantPutCalls: 1,
		},
	} {
		t.Run("refresh: "+tc.name+" returns 500 and keeps the token good", func(t *testing.T) {
			storage, setupSrv, clientID, _, refreshToken, _ := newEnv(t, "refresh-transient-user")
			spy := tc.spy(storage)
			srv := newHandlerWithStorage(spy, setupSrv.cipher, 5*time.Minute)

			w := doTokenRequest(srv, refreshForm(clientID, refreshToken))
			assert.Equal(t, http.StatusInternalServerError, w.Code, "response body: %s", w.Body.String())
			_, putCalls := spy.counts()
			assert.Equal(t, tc.wantPutCalls, putCalls)

			decodeTokenResponse(t, doTokenRequest(setupSrv, refreshForm(clientID, refreshToken)))
		})
	}
}

func TestAuthorizationCodeGrantGaps(t *testing.T) {
	ctx := context.Background()

	exchange := func(srv *Handler, clientID, code, verifier string) *httptest.ResponseRecorder {
		return doTokenRequest(srv, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {clientID},
			"code_verifier": {verifier},
		})
	}

	t.Run("a browser binding whose IdP session belongs to another user is refused", func(t *testing.T) {
		// The browser binding names the consenting user, but the IdP session it
		// points at is someone else's. Only the IdP-session user check stops the
		// MCP session being issued with the other user's upstream tokens.
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		spy := &tokenTestStorage{Storage: storage}
		srv := newHandlerWithStorage(spy, testCipher, 5*time.Minute)

		userID, otherUserID := "binding-user", "idp-session-owner"
		other := validIDPSession(otherUserID, "test-idp", &idpsession.OAuthToken{AccessToken: "other-users-token"}, nil)
		_, err = storage.client().Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{databroker_grpc.NewRecord(other)}})
		require.NoError(t, err)
		putBinding(ctx, t, storage, idpsession.NewBinding(other.GetId(), userID,
			idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
			&session.Session{Id: testBrowserSessionID(userID)}, nil))

		clientID := registerNoneAuthClient(ctx, t, storage)
		code, verifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

		w := exchange(srv, clientID, code, verifier)
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
		putBound, _ := spy.counts()
		assert.Zero(t, putBound, "no MCP session may be written")
	})

	t.Run("a binding of unknown protocol is refused", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)
		srv := newHandlerWithStorage(storage, testCipher, 5*time.Minute)

		userID := "unknown-protocol-user"
		idpSess := validIDPSession(userID, "test-idp", nil, nil)
		_, err = storage.client().Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{databroker_grpc.NewRecord(idpSess)}})
		require.NoError(t, err)
		putBinding(ctx, t, storage, idpsession.NewBinding(idpSess.GetId(), userID,
			idpsession.BindingProtocol_BINDING_PROTOCOL_UNKNOWN,
			&session.Session{Id: testBrowserSessionID(userID)}, nil))

		clientID := registerNoneAuthClient(ctx, t, storage)
		code, verifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)
		w := exchange(srv, clientID, code, verifier)
		assert.Equal(t, http.StatusBadRequest, w.Code, "response body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	for _, tc := range []struct {
		name string
		spy  func(*Storage) *tokenTestStorage
	}{
		{
			name: "GetActiveBinding unavailable",
			spy: func(s *Storage) *tokenTestStorage {
				return &tokenTestStorage{Storage: s, getBindingFunc: func(context.Context, string) (*idpsession.Binding, error) {
					return nil, status.Error(codes.Unavailable, "databroker unavailable")
				}}
			},
		},
		{
			name: "GetValidIDPSession unavailable",
			spy: func(s *Storage) *tokenTestStorage {
				return &tokenTestStorage{Storage: s, getIDPSessionFunc: func(context.Context, string) (*idpsession.IDPSession, error) {
					return nil, status.Error(codes.Unavailable, "databroker unavailable")
				}}
			},
		},
	} {
		t.Run("auth-code: "+tc.name+" returns 500, not invalid_grant", func(t *testing.T) {
			storage := setupTestDatabroker(ctx, t)
			testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
			require.NoError(t, err)
			srv := newHandlerWithStorage(tc.spy(storage), testCipher, 5*time.Minute)

			userID := "auth-code-transient-user"
			signIn(ctx, t, storage, validIDPSession(userID, "test-idp", nil, nil))
			clientID := registerNoneAuthClient(ctx, t, storage)
			code, verifier := sealAuthCode(ctx, t, storage, testCipher, clientID, userID, nil)

			w := exchange(srv, clientID, code, verifier)
			assert.Equal(t, http.StatusInternalServerError, w.Code, "response body: %s", w.Body.String())
		})
	}
}

// idpSessionGetFailingClient fails every Get of an IDPSession with err once
// armed, and every Put that deletes records with deleteErr when set.
type idpSessionGetFailingClient struct {
	databroker_grpc.DataBrokerServiceClient
	armed     atomic.Bool
	err       error
	deleteErr error
}

func (c *idpSessionGetFailingClient) Get(ctx context.Context, req *databroker_grpc.GetRequest, opts ...grpc.CallOption) (*databroker_grpc.GetResponse, error) {
	if c.armed.Load() && req.GetType() == protoutil.GetTypeURL(new(idpsession.IDPSession)) {
		return nil, c.err
	}
	return c.DataBrokerServiceClient.Get(ctx, req, opts...)
}

func (c *idpSessionGetFailingClient) Put(ctx context.Context, req *databroker_grpc.PutRequest, opts ...grpc.CallOption) (*databroker_grpc.PutResponse, error) {
	if c.deleteErr != nil && len(req.GetRecords()) > 0 && req.GetRecords()[0].GetDeletedAt() != nil {
		return nil, c.deleteErr
	}
	return c.DataBrokerServiceClient.Put(ctx, req, opts...)
}

func TestPutBoundSessionRereadGaps(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T, deleteErr error) (*Storage, *Storage, *idpSessionGetFailingClient, *session.Session) {
		t.Helper()
		direct := setupTestDatabroker(ctx, t)
		failing := &idpSessionGetFailingClient{
			DataBrokerServiceClient: direct.client(),
			err:                     status.Error(codes.Unavailable, "databroker unavailable"),
			deleteErr:               deleteErr,
		}
		_, err := direct.client().Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{
			databroker_grpc.NewRecord(&idpsession.IDPSession{Id: "idp-1", UserId: "u1"}),
		}})
		require.NoError(t, err)
		failing.armed.Store(true)
		sess := &session.Session{Id: "bound-1", UserId: "u1", IssuedAt: timestamppb.Now()}
		return direct, NewStorage(databroker_grpc.NewStaticClientGetter(failing)), failing, sess
	}

	t.Run("a re-read that fails for another reason rolls back and is not reported as NotFound", func(t *testing.T) {
		direct, storage, _, sess := setup(t, nil)

		_, err := storage.PutBoundSession(ctx, sess, "idp-1", nil)
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err),
			"a transient re-read failure must surface as a server error (500), not invalid_grant")

		_, _, err = direct.GetSession(ctx, sess.GetId())
		assert.Equal(t, codes.NotFound, status.Code(err), "session must be rolled back")
		_, err = direct.GetActiveBinding(ctx, sess.GetId())
		assert.Equal(t, codes.NotFound, status.Code(err), "binding must be rolled back")
	})
}
