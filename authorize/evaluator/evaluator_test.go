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
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestJSONMarshal(t *testing.T) {
	dbd := DataBrokerData{
		"type.googleapis.com/session.Session": map[string]interface{}{
			"SESSION_ID": &session.Session{
				UserId: "user1",
			},
		},
		"type.googleapis.com/directory.User": map[string]interface{}{
			"user1": &directory.User{
				Id:       "user1",
				GroupIds: []string{"group1", "group2"},
			},
		},
		"type.googleapis.com/directory.Group": map[string]interface{}{
			"group1": &directory.Group{
				Id:    "group1",
				Name:  "admin",
				Email: "admin@example.com",
			},
			"group2": &directory.Group{
				Id:   "group2",
				Name: "test",
			},
		},
	}

	bs, _ := json.Marshal(new(Evaluator).newInput(&Request{
		DataBrokerData: dbd,
		HTTP: RequestHTTP{
			Method: "GET",
			URL:    "https://example.com",
			Headers: map[string]string{
				"Accept": "application/json",
			},
			ClientCertificate: "CLIENT_CERTIFICATE",
		},
		Session: RequestSession{
			ID:                "SESSION_ID",
			ImpersonateEmail:  "y@example.com",
			ImpersonateGroups: []string{"group1"},
		},
	}, true))
	assert.JSONEq(t, `{
		"databroker_data": {
			"groups": ["admin", "admin@example.com", "test", "group1", "group2"],
			"session": {
				"user_id": "user1"
			}
		},
		"http": {
			"client_certificate": "CLIENT_CERTIFICATE",
			"headers": {
				"Accept": "application/json"
			},
			"method": "GET",
			"url": "https://example.com"
		},
		"session": {
			"id": "SESSION_ID",
			"impersonate_email": "y@example.com",
			"impersonate_groups": ["group1"]
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
		name string
		req  *Request
		want map[string]interface{}
	}{
		{
			"iss and aud",
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
			&Request{
				DataBrokerData: DataBrokerData{
					"type.googleapis.com/session.Session": map[string]interface{}{
						"SESSION_ID": &session.Session{
							IdToken: &session.IDToken{
								ExpiresAt: nowPb,
								IssuedAt:  nowPb,
							},
						},
					},
				},
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss": "authn.example.com",
				"aud": "example.com",
				"exp": now.Unix(),
				"iat": now.Unix(),
			},
		},
		{
			"with user",
			&Request{
				DataBrokerData: DataBrokerData{
					"type.googleapis.com/session.Session": map[string]interface{}{
						"SESSION_ID": &session.Session{
							UserId: "USER_ID",
						},
					},
					"type.googleapis.com/user.User": map[string]interface{}{
						"USER_ID": &user.User{
							Id:    "USER_ID",
							Name:  "foo",
							Email: "foo@example.com",
						},
					},
				},
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss":   "authn.example.com",
				"aud":   "example.com",
				"sub":   "USER_ID",
				"user":  "USER_ID",
				"email": "foo@example.com",
			},
		},
		{
			"with directory user",
			&Request{
				DataBrokerData: DataBrokerData{
					"type.googleapis.com/session.Session": map[string]interface{}{
						"SESSION_ID": &session.Session{
							UserId: "USER_ID",
						},
					},
					"type.googleapis.com/directory.User": map[string]interface{}{
						"USER_ID": &directory.User{
							Id:       "USER_ID",
							GroupIds: []string{"group1", "group2"},
						},
					},
					"type.googleapis.com/directory.Group": map[string]interface{}{
						"group1": &directory.Group{
							Id:    "group1",
							Name:  "admin",
							Email: "admin@example.com",
						},
						"group2": &directory.Group{
							Id:    "group2",
							Name:  "test",
							Email: "test@example.com",
						},
					},
				},
				HTTP: RequestHTTP{URL: "https://example.com"},
				Session: RequestSession{
					ID: "SESSION_ID",
				},
			},
			map[string]interface{}{
				"iss":    "authn.example.com",
				"aud":    "example.com",
				"groups": []string{"group1", "group2", "admin", "test"},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := New(&config.Options{
				AuthenticateURL: mustParseURL("https://authn.example.com"),
			}, NewStore())
			require.NoError(t, err)
			assert.Equal(t, tc.want, e.JWTPayload(tc.req))
		})
	}
}

func TestEvaluator_Evaluate(t *testing.T) {
	dbd := make(DataBrokerData)
	sessionID := uuid.New().String()
	userID := uuid.New().String()
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
	dbd.Update(&databroker.Record{
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
	dbd.Update(&databroker.Record{
		Version: "1",
		Type:    "type.googleapis.com/user.User",
		Id:      userID,
		Data:    data,
	})

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
			e, err := New(&config.Options{
				AuthenticateURL: mustParseURL("https://authn.example.com"),
				Policies:        tc.policies,
			}, NewStore())
			require.NoError(t, err)
			res, err := e.Evaluate(ctx, &Request{
				DataBrokerData: dbd,
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
	e, err := New(&config.Options{
		AuthenticateURL: mustParseURL("https://authn.example.com"),
	}, NewStore())
	if !assert.NoError(b, err) {
		return
	}

	lastSessionID := ""

	dbd := make(DataBrokerData)
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
		dbd.Update(&databroker.Record{
			Version: fmt.Sprint(i),
			Type:    "type.googleapis.com/session.Session",
			Id:      sessionID,
			Data:    data,
		})
		data, _ = ptypes.MarshalAny(&user.User{
			Version: fmt.Sprint(i),
			Id:      userID,
		})
		dbd.Update(&databroker.Record{
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
			DataBrokerData: dbd,
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
