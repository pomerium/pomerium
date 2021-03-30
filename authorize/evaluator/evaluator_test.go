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
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestJSONMarshal(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURLString = "https://authenticate.example.com"
	e, err := New(opt, NewStoreFromProtos(0,
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

			store := NewStoreFromProtos(0)
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
			store.UpdateRecord(0, &databroker.Record{
				Version: 1,
				Type:    "type.googleapis.com/session.Session",
				Id:      sessionID,
				Data:    data,
			})
			data, _ = ptypes.MarshalAny(&user.User{
				Version: "1",
				Id:      userID,
				Email:   "foo@example.com",
			})
			store.UpdateRecord(0, &databroker.Record{
				Version: 1,
				Type:    "type.googleapis.com/user.User",
				Id:      userID,
				Data:    data,
			})

			e, err := New(&config.Options{
				AuthenticateURLString: "https://authn.example.com",
				Policies:              tc.policies,
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
		AuthenticateURLString: "https://authn.example.com",
	}, store)
	if !assert.NoError(b, err) {
		return
	}

	lastSessionID := ""

	for i := 0; i < 100000; i++ {
		sessionID := uuid.New().String()
		lastSessionID = sessionID
		userID := uuid.New().String()
		data, _ := anypb.New(&session.Session{
			Version: fmt.Sprint(i),
			Id:      sessionID,
			UserId:  userID,
			IdToken: &session.IDToken{
				Issuer:   "benchmark",
				Subject:  userID,
				IssuedAt: timestamppb.Now(),
			},
			OauthToken: &session.OAuthToken{
				AccessToken:  "ACCESS TOKEN",
				TokenType:    "Bearer",
				RefreshToken: "REFRESH TOKEN",
			},
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    "type.googleapis.com/session.Session",
			Id:      sessionID,
			Data:    data,
		})
		data, _ = anypb.New(&user.User{
			Version: fmt.Sprint(i),
			Id:      userID,
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    "type.googleapis.com/user.User",
			Id:      userID,
			Data:    data,
		})

		data, _ = anypb.New(&directory.User{
			Version:  fmt.Sprint(i),
			Id:       userID,
			GroupIds: []string{"1", "2", "3", "4"},
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    data.TypeUrl,
			Id:      userID,
			Data:    data,
		})

		data, _ = anypb.New(&directory.Group{
			Version: fmt.Sprint(i),
			Id:      fmt.Sprint(i),
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    data.TypeUrl,
			Id:      fmt.Sprint(i),
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
