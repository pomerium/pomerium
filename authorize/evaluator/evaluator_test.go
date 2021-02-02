package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestJSONMarshal(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURL = mustParseURL("https://authenticate.example.com")
	e, err := New(opt, NewStoreFromProtos(
		&session.Session{
			UserId: "user1",
		},
		&directory.User{
			Id:       "user1",
			GroupIds: []string{"group1", "group2"},
		},
		&directory.Group{
			Id:    "group1",
			Name:  "admin",
			Email: "admin@example.com",
		},
		&directory.Group{
			Id:   "group2",
			Name: "test",
		},
	))
	require.NoError(t, err)
	bs, _ := json.Marshal(e.newInput(&Request{
		HTTP: RequestHTTP{
			Method: "GET",
			URL:    "https://example.com",
			Headers: map[string]string{
				"Accept": "application/json",
			},
			ClientCertificate: "CLIENT_CERTIFICATE",
		},
		Session: RequestSession{
			ID: "SESSION_ID",
		},
	}, true))
	assert.JSONEq(t, `{
		"http": {
			"client_certificate": "CLIENT_CERTIFICATE",
			"headers": {
				"Accept": "application/json"
			},
			"method": "GET",
			"url": "https://example.com"
		},
		"session": {
			"id": "SESSION_ID"
		},
		"is_valid_client_certificate": true
	}`, string(bs))
}

func TestEvaluator_SignedJWT(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURL = mustParseURL("https://authenticate.example.com")
	e, err := New(opt, NewStore())
	require.NoError(t, err)
	req := &Request{
		HTTP: RequestHTTP{
			Method: http.MethodGet,
			URL:    "https://example.com",
		},
	}
	signedJWT, err := e.SignedJWT(e.JWTPayload(req))
	require.NoError(t, err)
	assert.NotEmpty(t, signedJWT)

	payload, err := e.ParseSignedJWT(signedJWT)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
}

func TestEvaluator_JWTWithKID(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURL = mustParseURL("https://authenticate.example.com")
	opt.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUpCMFZkbko1VjEvbVlpYUlIWHhnd2Q0Yzd5YWRTeXMxb3Y0bzA1b0F3ekdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVUc1eENQMEpUVDFINklvbDhqS3VUSVBWTE0wNENnVzlQbEV5cE5SbVdsb29LRVhSOUhUMwpPYnp6aktZaWN6YjArMUt3VjJmTVRFMTh1dy82MXJVQ0JBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	e, err := New(opt, NewStore())
	require.NoError(t, err)
	req := &Request{
		HTTP: RequestHTTP{
			Method: http.MethodGet,
			URL:    "https://example.com",
		},
	}
	signedJWT, err := e.SignedJWT(e.JWTPayload(req))
	require.NoError(t, err)
	assert.NotEmpty(t, signedJWT)

	tok, err := jwt.ParseSigned(signedJWT)
	require.NoError(t, err)
	require.Len(t, tok.Headers, 1)
	assert.Equal(t, "5b419ade1895fec2d2def6cd33b1b9a018df60db231dc5ecb85cbed6d942813c", tok.Headers[0].KeyID)
}

func TestEvaluator_JWTPayload(t *testing.T) {
	nowPb := ptypes.TimestampNow()
	now, _ := ptypes.Timestamp(nowPb)
	tests := []struct {
		name  string
		store *Store
		req   *Request
		want  map[string]interface{}
	}{
		{
			"iss and aud",
			NewStore(),
			&Request{
				HTTP: RequestHTTP{URL: "https://example.com"},
			},
			map[string]interface{}{
				"iss": "authn.example.com",
				"aud": "example.com",
			},
		},
		{
			"with session",
			NewStoreFromProtos(&session.Session{
				Id: "SESSION_ID",
				IdToken: &session.IDToken{
					ExpiresAt: nowPb,
					IssuedAt:  nowPb,
				},
				ExpiresAt: nowPb,
			}),
			&Request{
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss": "authn.example.com",
				"jti": "SESSION_ID",
				"aud": "example.com",
				"exp": now.Unix(),
				"iat": now.Unix(),
			},
		},
		{
			"with service account",
			NewStoreFromProtos(&user.ServiceAccount{
				Id:        "SERVICE_ACCOUNT_ID",
				IssuedAt:  nowPb,
				ExpiresAt: nowPb,
			}),
			&Request{
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SERVICE_ACCOUNT_ID",
				},
			},
			map[string]interface{}{
				"iss": "authn.example.com",
				"jti": "SERVICE_ACCOUNT_ID",
				"aud": "example.com",
				"exp": now.Unix(),
				"iat": now.Unix(),
			},
		},
		{
			"with user",
			NewStoreFromProtos(&session.Session{
				Id:     "SESSION_ID",
				UserId: "USER_ID",
			}, &user.User{
				Id:    "USER_ID",
				Name:  "foo",
				Email: "foo@example.com",
			}),
			&Request{
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss":   "authn.example.com",
				"jti":   "SESSION_ID",
				"aud":   "example.com",
				"sub":   "USER_ID",
				"user":  "USER_ID",
				"email": "foo@example.com",
			},
		},
		{
			"with directory user",
			NewStoreFromProtos(
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&directory.User{
					Id:       "USER_ID",
					GroupIds: []string{"group1", "group2"},
				},
				&directory.Group{
					Id:    "group1",
					Name:  "admin",
					Email: "admin@example.com",
				},
				&directory.Group{
					Id:    "group2",
					Name:  "test",
					Email: "test@example.com",
				},
			),
			&Request{
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss":    "authn.example.com",
				"jti":    "SESSION_ID",
				"aud":    "example.com",
				"groups": []string{"group1", "group2", "admin", "test"},
			},
		},
		{
			"with impersonate",
			NewStoreFromProtos(
				&session.Session{
					Id:                "SESSION_ID",
					UserId:            "USER_ID",
					ImpersonateEmail:  proto.String("user@example.com"),
					ImpersonateGroups: []string{"admin", "test"},
				},
			),
			&Request{
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss":    "authn.example.com",
				"jti":    "SESSION_ID",
				"aud":    "example.com",
				"email":  "user@example.com",
				"groups": []string{"admin", "test"},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := New(&config.Options{
				AuthenticateURL: mustParseURL("https://authn.example.com"),
			}, tc.store)
			require.NoError(t, err)
			assert.Equal(t, tc.want, e.JWTPayload(tc.req))
		})
	}
}

func TestEvaluator_Evaluate(t *testing.T) {
	sessionID := uuid.New().String()
	userID := uuid.New().String()

	ctx := context.Background()
	allowedPolicy := []config.Policy{{From: "https://foo.com", AllowedUsers: []string{"foo@example.com"}}}
	forbiddenPolicy := []config.Policy{{From: "https://bar.com", AllowedUsers: []string{"bar@example.com"}}}

	tests := []struct {
		name           string
		reqURL         string
		policies       []config.Policy
		customPolicies []string
		sessionID      string
		expectedStatus int
	}{
		{"allowed", "https://foo.com/path", allowedPolicy, nil, sessionID, http.StatusOK},
		{"forbidden", "https://bar.com/path", forbiddenPolicy, nil, sessionID, http.StatusForbidden},
		{"unauthorized", "https://foo.com/path", allowedPolicy, nil, "", http.StatusUnauthorized},
		{"custom policy overwrite main policy", "https://foo.com/path", allowedPolicy, []string{"deny = true"}, sessionID, http.StatusForbidden},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewStoreFromProtos()
			data, _ := ptypes.MarshalAny(&session.Session{
				Version: "1",
				Id:      sessionID,
				UserId:  userID,
				IdToken: &session.IDToken{
					Issuer:   "TestEvaluatorEvaluate",
					Subject:  userID,
					IssuedAt: ptypes.TimestampNow(),
				},
				OauthToken: &session.OAuthToken{
					AccessToken:  "ACCESS TOKEN",
					TokenType:    "Bearer",
					RefreshToken: "REFRESH TOKEN",
				},
			})
			store.UpdateRecord(&databroker.Record{
				Version: "1",
				Type:    "type.googleapis.com/session.Session",
				Id:      sessionID,
				Data:    data,
			})
			data, _ = ptypes.MarshalAny(&user.User{
				Version: "1",
				Id:      userID,
				Email:   "foo@example.com",
			})
			store.UpdateRecord(&databroker.Record{
				Version: "1",
				Type:    "type.googleapis.com/user.User",
				Id:      userID,
				Data:    data,
			})

			e, err := New(&config.Options{
				AuthenticateURL: mustParseURL("https://authn.example.com"),
				Policies:        tc.policies,
			}, store)
			require.NoError(t, err)
			res, err := e.Evaluate(ctx, &Request{
				HTTP:           RequestHTTP{Method: "GET", URL: tc.reqURL},
				Session:        RequestSession{ID: tc.sessionID},
				CustomPolicies: tc.customPolicies,
			})
			require.NoError(t, err)
			assert.NotNil(t, res)
			assert.Equal(t, tc.expectedStatus, res.Status)
		})
	}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func BenchmarkEvaluator_Evaluate(b *testing.B) {
	store := NewStore()
	e, err := New(&config.Options{
		AuthenticateURL: mustParseURL("https://authn.example.com"),
	}, store)
	if !assert.NoError(b, err) {
		return
	}

	lastSessionID := ""

	for i := 0; i < 100; i++ {
		sessionID := uuid.New().String()
		lastSessionID = sessionID
		userID := uuid.New().String()
		data, _ := ptypes.MarshalAny(&session.Session{
			Version: fmt.Sprint(i),
			Id:      sessionID,
			UserId:  userID,
			IdToken: &session.IDToken{
				Issuer:   "benchmark",
				Subject:  userID,
				IssuedAt: ptypes.TimestampNow(),
			},
			OauthToken: &session.OAuthToken{
				AccessToken:  "ACCESS TOKEN",
				TokenType:    "Bearer",
				RefreshToken: "REFRESH TOKEN",
			},
		})
		store.UpdateRecord(&databroker.Record{
			Version: fmt.Sprint(i),
			Type:    "type.googleapis.com/session.Session",
			Id:      sessionID,
			Data:    data,
		})
		data, _ = ptypes.MarshalAny(&user.User{
			Version: fmt.Sprint(i),
			Id:      userID,
		})
		store.UpdateRecord(&databroker.Record{
			Version: fmt.Sprint(i),
			Type:    "type.googleapis.com/user.User",
			Id:      userID,
			Data:    data,
		})
	}

	b.ResetTimer()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		e.Evaluate(ctx, &Request{
			HTTP: RequestHTTP{
				Method:  "GET",
				URL:     "https://example.com/path",
				Headers: map[string]string{},
			},
			Session: RequestSession{
				ID: lastSessionID,
			},
		})
	}
}
