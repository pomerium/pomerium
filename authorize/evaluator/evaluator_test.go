package evaluator

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestEvaluator(t *testing.T) {
	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey, jose.ES256)
	require.NoError(t, err)

	eval := func(t *testing.T, options []Option, data []proto.Message, req *Request) (*Result, error) {
		store := NewStoreFromProtos(math.MaxUint64, data...)
		store.UpdateIssuer("authenticate.example.com")
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := New(context.Background(), store, options...)
		require.NoError(t, err)
		return e.Evaluate(context.Background(), req)
	}

	policies := []config.Policy{
		{
			To:                               config.WeightedURLs{{URL: *mustParseURL("https://to1.example.com")}},
			AllowPublicUnauthenticatedAccess: true,
		},
		{
			To:                               config.WeightedURLs{{URL: *mustParseURL("https://to2.example.com")}},
			AllowPublicUnauthenticatedAccess: true,
			KubernetesServiceAccountToken:    "KUBERNETES",
		},
		{
			To:                               config.WeightedURLs{{URL: *mustParseURL("https://to3.example.com")}},
			AllowPublicUnauthenticatedAccess: true,
			EnableGoogleCloudServerlessAuthentication: true,
		},
		{
			To:           config.WeightedURLs{{URL: *mustParseURL("https://to4.example.com")}},
			AllowedUsers: []string{"a@example.com"},
		},
		{
			To: config.WeightedURLs{{URL: *mustParseURL("https://to5.example.com")}},
			SubPolicies: []config.SubPolicy{
				{
					AllowedUsers: []string{"a@example.com"},
				},
			},
		},
		{
			To:           config.WeightedURLs{{URL: *mustParseURL("https://to6.example.com")}},
			AllowedUsers: []string{"example/1234"},
		},
		{
			To:             config.WeightedURLs{{URL: *mustParseURL("https://to7.example.com")}},
			AllowedDomains: []string{"example.com"},
		},
		{
			To:            config.WeightedURLs{{URL: *mustParseURL("https://to8.example.com")}},
			AllowedGroups: []string{"group1@example.com"},
		},
		{
			To:                        config.WeightedURLs{{URL: *mustParseURL("https://to9.example.com")}},
			AllowAnyAuthenticatedUser: true,
		},
	}
	options := []Option{
		WithAuthenticateURL("https://authn.example.com"),
		WithClientCA([]byte(testCA)),
		WithPolicies(policies),
	}

	t.Run("client certificate", func(t *testing.T) {
		t.Run("invalid", func(t *testing.T) {
			res, err := eval(t, options, nil, &Request{
				Policy: &policies[0],
			})
			require.NoError(t, err)
			assert.Equal(t, &Denial{Status: 495, Message: "invalid client certificate"}, res.Deny)
		})
		t.Run("valid", func(t *testing.T) {
			res, err := eval(t, options, nil, &Request{
				Policy: &policies[0],
				HTTP: RequestHTTP{
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.Nil(t, res.Deny)
		})
	})
	t.Run("identity_headers", func(t *testing.T) {
		t.Run("kubernetes", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:                "session1",
					UserId:            "user1",
					ImpersonateGroups: []string{"i1", "i2"},
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Policy: &policies[1],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.Equal(t, "a@example.com", res.Headers.Get("Impersonate-User"))
			assert.Equal(t, "i1,i2", res.Headers.Get("Impersonate-Group"))
		})
		t.Run("google_cloud_serverless", func(t *testing.T) {
			withMockGCP(t, func() {
				res, err := eval(t, options, []proto.Message{
					&session.Session{
						Id:                "session1",
						UserId:            "user1",
						ImpersonateGroups: []string{"i1", "i2"},
					},
					&user.User{
						Id:    "user1",
						Email: "a@example.com",
					},
				}, &Request{
					Policy: &policies[2],
					Session: RequestSession{
						ID: "session1",
					},
					HTTP: RequestHTTP{
						Method:            "GET",
						URL:               "https://from.example.com",
						ClientCertificate: testValidCert,
					},
				})
				require.NoError(t, err)
				assert.NotEmpty(t, res.Headers.Get("Authorization"))
			})
		})
	})
	t.Run("email", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Policy: &policies[3],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.True(t, res.Allow)
		})
		t.Run("allowed sub", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Policy: &policies[4],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.True(t, res.Allow)
		})
		t.Run("denied", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id:    "user1",
					Email: "b@example.com",
				},
			}, &Request{
				Policy: &policies[3],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.False(t, res.Allow)
		})
	})
	t.Run("impersonate email", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&user.ServiceAccount{
					Id:               "session1",
					UserId:           "user1",
					ImpersonateEmail: proto.String("a@example.com"),
				},
				&user.User{
					Id:    "user1",
					Email: "b@example.com",
				},
			}, &Request{
				Policy: &policies[3],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.True(t, res.Allow)
		})
		t.Run("denied", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:               "session1",
					UserId:           "user1",
					ImpersonateEmail: proto.String("b@example.com"),
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Policy: &policies[3],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.False(t, res.Allow)
		})
	})
	t.Run("user_id", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "example/1234",
			},
			&user.User{
				Id:    "example/1234",
				Email: "a@example.com",
			},
		}, &Request{
			Policy: &policies[5],
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method:            "GET",
				URL:               "https://from.example.com",
				ClientCertificate: testValidCert,
			},
		})
		require.NoError(t, err)
		assert.True(t, res.Allow)
	})
	t.Run("domain", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "user1",
			},
			&user.User{
				Id:    "user1",
				Email: "a@example.com",
			},
		}, &Request{
			Policy: &policies[6],
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method:            "GET",
				URL:               "https://from.example.com",
				ClientCertificate: testValidCert,
			},
		})
		require.NoError(t, err)
		assert.True(t, res.Allow)
	})
	t.Run("impersonate domain", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:               "session1",
				UserId:           "user1",
				ImpersonateEmail: proto.String("a@example.com"),
			},
			&user.User{
				Id:    "user1",
				Email: "a@notexample.com",
			},
		}, &Request{
			Policy: &policies[6],
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method:            "GET",
				URL:               "https://from.example.com",
				ClientCertificate: testValidCert,
			},
		})
		require.NoError(t, err)
		assert.True(t, res.Allow)
	})
	t.Run("groups", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "user1",
			},
			&user.User{
				Id:    "user1",
				Email: "a@example.com",
			},
			&directory.User{
				Id:       "user1",
				GroupIds: []string{"group1"},
			},
			&directory.Group{
				Id:    "group1",
				Name:  "group1name",
				Email: "group1@example.com",
			},
		}, &Request{
			Policy: &policies[7],
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method:            "GET",
				URL:               "https://from.example.com",
				ClientCertificate: testValidCert,
			},
		})
		require.NoError(t, err)
		assert.True(t, res.Allow)
	})
	t.Run("impersonate groups", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:                "session1",
				UserId:            "user1",
				ImpersonateGroups: []string{"group1"},
			},
			&user.User{
				Id:    "user1",
				Email: "a@example.com",
			},
			&directory.User{
				Id: "user1",
			},
			&directory.Group{
				Id:    "group1",
				Name:  "group1name",
				Email: "group1@example.com",
			},
		}, &Request{
			Policy: &policies[7],
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method:            "GET",
				URL:               "https://from.example.com",
				ClientCertificate: testValidCert,
			},
		})
		require.NoError(t, err)
		assert.True(t, res.Allow)
	})
	t.Run("any authenticated user", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "user1",
			},
			&user.User{
				Id: "user1",
			},
		}, &Request{
			Policy: &policies[8],
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method:            "GET",
				URL:               "https://from.example.com",
				ClientCertificate: testValidCert,
			},
		})
		require.NoError(t, err)
		assert.True(t, res.Allow)
	})
	t.Run("carry over assertion header", func(t *testing.T) {
		tcs := []struct {
			src             map[string]string
			jwtAssertionFor string
		}{
			{map[string]string{}, ""},
			{map[string]string{
				http.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertion): "identity-a",
			}, "identity-a"},
			{map[string]string{
				http.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertionFor): "identity-a",
				http.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertion):    "identity-b",
			}, "identity-a"},
		}
		for _, tc := range tcs {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id: "user1",
				},
			}, &Request{
				Policy: &policies[8],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
					Headers:           tc.src,
				},
			})
			if assert.NoError(t, err) {
				assert.Equal(t, tc.jwtAssertionFor, res.Headers.Get(httputil.HeaderPomeriumJWTAssertionFor))
			}
		}
	})
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

	policies := []config.Policy{
		{
			From: "https://from.example.com",
			To: config.WeightedURLs{
				{URL: *mustParseURL("https://to.example.com")},
			},
			AllowedUsers: []string{"SOME_USER"},
		},
	}
	options := []Option{
		WithAuthenticateURL("https://authn.example.com"),
		WithPolicies(policies),
	}

	e, err := New(context.Background(), store, options...)
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
		_, _ = e.Evaluate(ctx, &Request{
			Policy: &policies[0],
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
