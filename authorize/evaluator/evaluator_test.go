package evaluator

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestEvaluator(t *testing.T) {
	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)

	eval := func(t *testing.T, options []Option, data []proto.Message, req *Request) (*Result, error) {
		ctx := context.Background()
		ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier(data...))
		store := store.New()
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := New(ctx, store, options...)
		require.NoError(t, err)
		return e.Evaluate(ctx, req)
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
			To:                        config.WeightedURLs{{URL: *mustParseURL("https://to9.example.com")}},
			AllowAnyAuthenticatedUser: true,
		},
		{
			To: config.WeightedURLs{{URL: *mustParseURL("https://to10.example.com")}},
			Policy: &config.PPLPolicy{
				Policy: &parser.Policy{
					Rules: []parser.Rule{{
						Action: parser.ActionAllow,
						Or: []parser.Criterion{{
							Name: "http_method", Data: parser.Object{
								"is": parser.String("GET"),
							},
						}},
					}},
				},
			},
		},
		{
			To: config.WeightedURLs{{URL: *mustParseURL("https://to11.example.com")}},
			Policy: &config.PPLPolicy{
				Policy: &parser.Policy{
					Rules: []parser.Rule{{
						Action: parser.ActionAllow,
						Or: []parser.Criterion{{
							Name: "http_path", Data: parser.Object{
								"is": parser.String("/test"),
							},
						}},
					}},
				},
			},
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
			assert.Equal(t, NewRuleResult(true, criteria.ReasonInvalidClientCertificate), res.Deny)
		})
		t.Run("valid", func(t *testing.T) {
			res, err := eval(t, options, nil, &Request{
				Policy: &policies[0],
				HTTP: RequestHTTP{
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.False(t, res.Deny.Value)
		})
	})
	t.Run("identity_headers", func(t *testing.T) {
		t.Run("kubernetes", func(t *testing.T) {
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
		})
		t.Run("google_cloud_serverless", func(t *testing.T) {
			withMockGCP(t, func() {
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
			assert.True(t, res.Allow.Value)
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
			assert.True(t, res.Allow.Value)
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
			assert.False(t, res.Allow.Value)
		})
	})
	t.Run("impersonate email", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&session.Session{
					Id:                   "session2",
					UserId:               "user2",
					ImpersonateSessionId: proto.String("session1"),
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Policy: &policies[3],
				Session: RequestSession{
					ID: "session2",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.True(t, res.Allow.Value)
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
		assert.True(t, res.Allow.Value)
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
		assert.True(t, res.Allow.Value)
	})
	t.Run("impersonate domain", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "user1",
			},
			&session.Session{
				Id:                   "session2",
				UserId:               "user2",
				ImpersonateSessionId: proto.String("session1"),
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
		assert.True(t, res.Allow.Value)
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
		assert.True(t, res.Allow.Value)
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
	t.Run("http method", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{}, &Request{
			Policy: &policies[8],
			HTTP: NewRequestHTTP(
				"GET",
				*mustParseURL("https://from.example.com/"),
				nil,
				testValidCert,
				"",
			),
		})
		require.NoError(t, err)
		assert.True(t, res.Allow.Value)
	})
	t.Run("http path", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{}, &Request{
			Policy: &policies[9],
			HTTP: NewRequestHTTP(
				"POST",
				*mustParseURL("https://from.example.com/test"),
				nil,
				testValidCert,
				"",
			),
		})
		require.NoError(t, err)
		assert.True(t, res.Allow.Value)
	})
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
