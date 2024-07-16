package evaluator_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
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

	eval := func(t *testing.T, options []evaluator.Option, data []proto.Message, req *evaluator.Request) (*evaluator.Result, error) {
		ctx := context.Background()
		ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier(data...))
		store := store.New()
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := evaluator.New(ctx, store, nil, options...)
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
			To:                        config.WeightedURLs{{URL: *mustParseURL("https://to8.example.com")}},
			AllowAnyAuthenticatedUser: true,
		},
		{
			To: config.WeightedURLs{{URL: *mustParseURL("https://to9.example.com")}},
			Policy: &config.PPLPolicy{
				Policy: &parser.Policy{
					Rules: []parser.Rule{{
						Action: parser.ActionAllow,
						Or: []parser.Criterion{{
							Name: "http_method", Data: parser.Object{
								"is": parser.String(http.MethodGet),
							},
						}},
					}},
				},
			},
		},
		{
			To: config.WeightedURLs{{URL: *mustParseURL("https://to10.example.com")}},
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
		{
			To:                    config.WeightedURLs{{URL: *mustParseURL("https://to11.example.com")}},
			AllowedUsers:          []string{"a@example.com"},
			TLSDownstreamClientCA: base64.StdEncoding.EncodeToString([]byte(testCA)),
		},
		{
			To:           config.WeightedURLs{{URL: *mustParseURL("https://to12.example.com")}},
			AllowedUsers: []string{"a@example.com"},
			Policy: &config.PPLPolicy{
				Policy: &parser.Policy{
					Rules: []parser.Rule{{
						Action: parser.ActionDeny,
						Or:     []parser.Criterion{{Name: "invalid_client_certificate"}},
					}},
				},
			},
		},
	}
	options := []evaluator.Option{
		evaluator.WithAuthenticateURL("https://authn.example.com"),
		evaluator.WithPolicies(policies),
	}

	validCertInfo := evaluator.ClientCertificateInfo{
		Presented: true,
		Leaf:      testValidCert,
	}

	t.Run("client certificate (default CA)", func(t *testing.T) {
		// Clone the existing options and add a default client CA.
		options := append([]evaluator.Option(nil), options...)
		options = append(options, evaluator.WithClientCA([]byte(testCA)),
			evaluator.WithAddDefaultClientCertificateRule(true))
		t.Run("missing", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[0],
			})
			require.NoError(t, err)
			assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonClientCertificateRequired), res.Deny)
		})
		t.Run("invalid", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[0],
				HTTP: evaluator.RequestHTTP{
					ClientCertificate: evaluator.ClientCertificateInfo{Presented: true},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonInvalidClientCertificate), res.Deny)
		})
		t.Run("valid", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[0],
				HTTP: evaluator.RequestHTTP{
					ClientCertificate: validCertInfo,
				},
			})
			require.NoError(t, err)
			assert.False(t, res.Deny.Value)
		})
	})
	t.Run("client certificate (per-policy CA)", func(t *testing.T) {
		// Clone existing options and add the default client certificate rule.
		options := append([]evaluator.Option(nil), options...)
		options = append(options, evaluator.WithAddDefaultClientCertificateRule(true))
		t.Run("missing", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[10],
			})
			require.NoError(t, err)
			assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonClientCertificateRequired), res.Deny)
		})
		t.Run("invalid", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[10],
				HTTP: evaluator.RequestHTTP{
					ClientCertificate: evaluator.ClientCertificateInfo{
						Presented: true,
						Leaf:      testUntrustedCert,
					},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonInvalidClientCertificate), res.Deny)
		})
		t.Run("valid", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[10],
				HTTP: evaluator.RequestHTTP{
					ClientCertificate: validCertInfo,
				},
			})
			require.NoError(t, err)
			assert.False(t, res.Deny.Value)
		})
	})
	t.Run("explicit client certificate rule", func(t *testing.T) {
		// Clone the existing options and add a default client CA (but no
		// default deny rule).
		options := append([]evaluator.Option(nil), options...)
		options = append(options, evaluator.WithClientCA([]byte(testCA)))
		t.Run("invalid but allowed", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[0], // no explicit deny rule
				HTTP: evaluator.RequestHTTP{
					ClientCertificate: evaluator.ClientCertificateInfo{
						Presented: true,
						Leaf:      testUntrustedCert,
					},
				},
			})
			require.NoError(t, err)
			assert.False(t, res.Deny.Value)
		})
		t.Run("invalid", func(t *testing.T) {
			res, err := eval(t, options, nil, &evaluator.Request{
				Policy: &policies[11], // policy has explicit deny rule
				HTTP: evaluator.RequestHTTP{
					ClientCertificate: evaluator.ClientCertificateInfo{
						Presented: true,
						Leaf:      testUntrustedCert,
					},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonInvalidClientCertificate), res.Deny)
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
			}, &evaluator.Request{
				Policy: &policies[1],
				Session: evaluator.RequestSession{
					ID: "session1",
				},
				HTTP: evaluator.RequestHTTP{
					Method: http.MethodGet,
					URL:    "https://from.example.com",
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
				}, &evaluator.Request{
					Policy: &policies[2],
					Session: evaluator.RequestSession{
						ID: "session1",
					},
					HTTP: evaluator.RequestHTTP{
						Method: http.MethodGet,
						URL:    "https://from.example.com",
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
			}, &evaluator.Request{
				Policy: &policies[3],
				Session: evaluator.RequestSession{
					ID: "session1",
				},
				HTTP: evaluator.RequestHTTP{
					Method: http.MethodGet,
					URL:    "https://from.example.com",
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
			}, &evaluator.Request{
				Policy: &policies[4],
				Session: evaluator.RequestSession{
					ID: "session1",
				},
				HTTP: evaluator.RequestHTTP{
					Method: http.MethodGet,
					URL:    "https://from.example.com",
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
			}, &evaluator.Request{
				Policy: &policies[3],
				Session: evaluator.RequestSession{
					ID: "session1",
				},
				HTTP: evaluator.RequestHTTP{
					Method: http.MethodGet,
					URL:    "https://from.example.com",
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
			}, &evaluator.Request{
				Policy: &policies[3],
				Session: evaluator.RequestSession{
					ID: "session2",
				},
				HTTP: evaluator.RequestHTTP{
					Method: http.MethodGet,
					URL:    "https://from.example.com",
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
		}, &evaluator.Request{
			Policy: &policies[5],
			Session: evaluator.RequestSession{
				ID: "session1",
			},
			HTTP: evaluator.RequestHTTP{
				Method: http.MethodGet,
				URL:    "https://from.example.com",
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
		}, &evaluator.Request{
			Policy: &policies[6],
			Session: evaluator.RequestSession{
				ID: "session1",
			},
			HTTP: evaluator.RequestHTTP{
				Method: http.MethodGet,
				URL:    "https://from.example.com",
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
		}, &evaluator.Request{
			Policy: &policies[6],
			Session: evaluator.RequestSession{
				ID: "session1",
			},
			HTTP: evaluator.RequestHTTP{
				Method: http.MethodGet,
				URL:    "https://from.example.com",
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
		}, &evaluator.Request{
			Policy: &policies[7],
			Session: evaluator.RequestSession{
				ID: "session1",
			},
			HTTP: evaluator.RequestHTTP{
				Method: http.MethodGet,
				URL:    "https://from.example.com",
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
				httputil.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertion): "identity-a",
			}, "identity-a"},
			{map[string]string{
				httputil.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertionFor): "identity-a",
				httputil.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertion):    "identity-b",
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
			}, &evaluator.Request{
				Policy: &policies[8],
				Session: evaluator.RequestSession{
					ID: "session1",
				},
				HTTP: evaluator.RequestHTTP{
					Method:  http.MethodGet,
					URL:     "https://from.example.com",
					Headers: tc.src,
				},
			})
			if assert.NoError(t, err) {
				assert.Equal(t, tc.jwtAssertionFor, res.Headers.Get(httputil.HeaderPomeriumJWTAssertionFor))
			}
		}
	})
	t.Run("http method", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{}, &evaluator.Request{
			Policy: &policies[8],
			HTTP: evaluator.NewRequestHTTP(
				http.MethodGet,
				*mustParseURL("https://from.example.com/"),
				nil,
				evaluator.ClientCertificateInfo{},
				"",
			),
		})
		require.NoError(t, err)
		assert.True(t, res.Allow.Value)
	})
	t.Run("http path", func(t *testing.T) {
		res, err := eval(t, options, []proto.Message{}, &evaluator.Request{
			Policy: &policies[9],
			HTTP: evaluator.NewRequestHTTP(
				"POST",
				*mustParseURL("https://from.example.com/test"),
				nil,
				evaluator.ClientCertificateInfo{},
				"",
			),
		})
		require.NoError(t, err)
		assert.True(t, res.Allow.Value)
	})
}

func TestPolicyEvaluatorReuse(t *testing.T) {
	ctx := context.Background()

	store := store.New()

	policies := []config.Policy{
		{To: singleToURL("https://to1.example.com")},
		{To: singleToURL("https://to2.example.com")},
		{To: singleToURL("https://to3.example.com")},
		{To: singleToURL("https://to4.example.com")},
	}

	options := []evaluator.Option{
		evaluator.WithPolicies(policies),
	}

	initial, err := evaluator.New(ctx, store, nil, options...)
	require.NoError(t, err)

	initialEvaluators := initial.Cache().Clone()

	assertPolicyEvaluatorReused := func(t *testing.T, e *evaluator.Evaluator, p *config.Policy) {
		t.Helper()
		routeID, err := p.RouteID()
		require.NoError(t, err)
		p1, ok := initialEvaluators.LookupEvaluator(routeID)
		require.True(t, ok)
		require.NotNil(t, p1)
		p2, ok := e.Cache().LookupEvaluator(routeID)
		require.True(t, ok)
		assert.Same(t, p1, p2, routeID)
	}

	assertPolicyEvaluatorUpdated := func(t *testing.T, e *evaluator.Evaluator, p *config.Policy) {
		t.Helper()
		routeID, err := p.RouteID()
		require.NoError(t, err)
		p1, ok := initialEvaluators.LookupEvaluator(routeID)
		require.True(t, ok)
		require.NotNil(t, p1)
		p2, ok := e.Cache().LookupEvaluator(routeID)
		require.True(t, ok)
		require.NotNil(t, p2)
		assert.NotSame(t, p1, p2, routeID)
	}

	// If the evaluatorConfig is identical, all of the policy evaluators should
	// be reused.
	t.Run("identical", func(t *testing.T) {
		e, err := evaluator.New(ctx, store, initial, options...)
		require.NoError(t, err)
		for i := range policies {
			assertPolicyEvaluatorReused(t, e, &policies[i])
		}
	})

	assertNoneReused := func(t *testing.T, o evaluator.Option) {
		e, err := evaluator.New(ctx, store, initial, append(options, o)...)
		require.NoError(t, err)
		for i := range policies {
			assertPolicyEvaluatorUpdated(t, e, &policies[i])
		}
	}

	// If any of the evaluatorConfig fields besides the Policies change, no
	// policy evaluators should be reused.
	t.Run("ClientCA changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithClientCA([]byte("dummy-ca")))
	})
	t.Run("ClientCRL changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithClientCRL([]byte("dummy-crl")))
	})
	t.Run("AddDefaultClientCertificateRule changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithAddDefaultClientCertificateRule(true))
	})
	t.Run("ClientCertConstraints changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithClientCertConstraints(&evaluator.ClientCertConstraints{MaxVerifyDepth: 3}))
	})
	t.Run("SigningKey changed", func(t *testing.T) {
		signingKey, err := cryptutil.NewSigningKey()
		require.NoError(t, err)
		encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
		require.NoError(t, err)
		assertNoneReused(t, evaluator.WithSigningKey(encodedSigningKey))
	})
	t.Run("AuthenticateURL changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithAuthenticateURL("authenticate.example.com"))
	})
	t.Run("GoogleCloudServerlessAuthenticationServiceAccount changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithGoogleCloudServerlessAuthenticationServiceAccount("dummy-account"))
	})
	t.Run("JWTClaimsHeaders changed", func(t *testing.T) {
		assertNoneReused(t, evaluator.WithJWTClaimsHeaders(config.JWTClaimHeaders{"dummy": "header"}))
	})

	// If some policies have changed, but the evaluatorConfig is otherwise
	// identical, only evaluators for the changed policies should be updated.
	t.Run("policies changed", func(t *testing.T) {
		// Make changes to some of the policies.
		newPolicies := []config.Policy{
			{To: singleToURL("https://to1.example.com")},
			{
				To:           singleToURL("https://to2.example.com"),
				AllowedUsers: []string{"user-id-1"},
			}, // change just the policy itself
			{To: singleToURL("https://to3.example.com")},
			{To: singleToURL("https://foo.example.com"), // change route ID too
				AllowAnyAuthenticatedUser: true},
		}

		e, err := evaluator.New(ctx, store, initial, evaluator.WithPolicies(newPolicies))
		require.NoError(t, err)

		// Only the first and the third policy evaluators should be reused.
		assertPolicyEvaluatorReused(t, e, &newPolicies[0])
		assertPolicyEvaluatorUpdated(t, e, &newPolicies[1])
		assertPolicyEvaluatorReused(t, e, &newPolicies[2])

		// The last policy shouldn't correspond with any of the initial policy
		// evaluators.
		rid, err := newPolicies[3].RouteID()
		require.NoError(t, err)
		_, exists := initialEvaluators.LookupEvaluator(rid)
		assert.False(t, exists, "initial evaluator should not have a policy for route ID", rid)
		eval, ok := e.Cache().LookupEvaluator(rid)
		assert.True(t, ok, "new evaluator should have a policy for route ID", rid)
		assert.NotNil(t, eval)
	})
}

func singleToURL(url string) config.WeightedURLs {
	return config.WeightedURLs{{URL: *mustParseURL(url)}}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func BenchmarkEvaluator(b *testing.B) {
	log.SetLevel(zerolog.WarnLevel)

	b.Run("append new policies", func(b *testing.B) {
		b.Run("same ppl for all routes", func(b *testing.B) {
			store := store.New()
			ppl := `
allow:
  and:
    - email:
        is: foo@bar.com
`
			var pplPolicy config.PPLPolicy
			err := yaml.Unmarshal([]byte(ppl), &pplPolicy)
			require.NoError(b, err)

			var e *evaluator.Evaluator
			policies := make([]config.Policy, 0, 4096)
			for i := 0; i < b.N; i++ {
				policies = append(policies, config.Policy{
					From:   fmt.Sprintf("https://from%d.example.com", i),
					To:     singleToURL(fmt.Sprintf("https://to%d.example.com", i)),
					Policy: &pplPolicy,
				})
				var err error
				e, err = evaluator.New(context.Background(), store, e, evaluator.WithPolicies(policies))
				require.NoError(b, err)
				require.Equal(b, e.Cache().NumCachedEvaluators(), len(policies))
			}
		})
		b.Run("unique ppl per route", func(b *testing.B) {
			store := store.New()
			newPPLPolicy := func(i int) *config.PPLPolicy {
				ppl := fmt.Sprintf(`
allow:
  and:
    - email:
        is: user-%d@example.com
`, i)
				var pplPolicy config.PPLPolicy
				err := yaml.Unmarshal([]byte(ppl), &pplPolicy)
				require.NoError(b, err)
				return &pplPolicy
			}

			var e *evaluator.Evaluator
			policies := make([]config.Policy, 0, 4096)
			timeout := time.Minute
			for i := 0; i < b.N; i++ {
				policies = append(policies, config.Policy{
					From:            fmt.Sprintf("https://from%d.example.com", i),
					To:              singleToURL(fmt.Sprintf("https://to%d.example.com", i)),
					Policy:          newPPLPolicy(i),
					UpstreamTimeout: &timeout,
					TLSSkipVerify:   true,
				})
				var err error
				e, err = evaluator.New(context.Background(), store, e, evaluator.WithPolicies(policies))
				require.NoError(b, err)
				require.Equal(b, e.Cache().NumCachedEvaluators(), len(policies))
			}
		})
	})
}
