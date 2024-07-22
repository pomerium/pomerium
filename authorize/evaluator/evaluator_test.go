package evaluator_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/trace"
	"strings"
	"testing"
	"time"

	xtrace "golang.org/x/exp/trace"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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

	initialEvaluators := initial.XEvaluatorCache().XClone()

	assertPolicyEvaluatorReused := func(t *testing.T, e *evaluator.Evaluator, p *config.Policy) {
		t.Helper()
		routeID, err := p.RouteID()
		require.NoError(t, err)
		p1, ok := initialEvaluators.LookupEvaluator(routeID)
		require.True(t, ok)
		require.NotNil(t, p1)
		p2, ok := e.XEvaluatorCache().LookupEvaluator(routeID)
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
		p2, ok := e.XEvaluatorCache().LookupEvaluator(routeID)
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
		eval, ok := e.XEvaluatorCache().LookupEvaluator(rid)
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
				require.Equal(b, e.XEvaluatorCache().NumCachedEvaluators(), len(policies))
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
				require.Equal(b, e.XEvaluatorCache().NumCachedEvaluators(), len(policies))
			}
		})
	})
}

type logAssertion struct {
	before time.Time
	after  time.Time
	msg    string
}

type logAssertionGroup struct {
	before            time.Time
	after             time.Time
	unorderedMessages []string
}

type GetOrCreatePolicyEvaluatorsSuite struct {
	suite.Suite

	logAssertions []any
	traceBuffer   bytes.Buffer
}

var _ interface {
	suite.SetupTestSuite
	suite.TearDownTestSuite
} = (*GetOrCreatePolicyEvaluatorsSuite)(nil)

const (
	staticPolicyFormat = `
allow:
  and:
    - email:
        is: foo@example.com
`
	uniquePerUserPolicyFormat = `
allow:
  and:
    - email:
        is: user-%d@example.com
`
)

func (s *GetOrCreatePolicyEvaluatorsSuite) generateRoutes(start, n int, policyFormat string) []config.Policy {
	newPPLPolicy := func(i int, format string) *config.PPLPolicy {
		var pplPolicy config.PPLPolicy
		if strings.Contains(format, "%d") {
			format = fmt.Sprintf(format, i)
		}
		err := yaml.Unmarshal([]byte(format), &pplPolicy)
		s.NoError(err)
		return &pplPolicy
	}
	list := make([]config.Policy, 0, n)
	for i := 0; i < n; i++ {
		list = append(list, config.Policy{
			From:   fmt.Sprintf("https://from%d.example.com", start+i),
			To:     singleToURL(fmt.Sprintf("https://to%d.example.com", start+i)),
			Policy: newPPLPolicy(start+i, policyFormat),
		})
	}
	return list
}

func (s *GetOrCreatePolicyEvaluatorsSuite) SetupTest() {
	s.traceBuffer.Reset()
	s.logAssertions = []any{}
	s.Require().NoError(trace.Start(&s.traceBuffer))
}

func (s *GetOrCreatePolicyEvaluatorsSuite) TearDownTest() {
	trace.Stop()
	traceReader, err := xtrace.NewReader(&s.traceBuffer)
	s.Require().NoError(err)
	logsReceived := []xtrace.Event{}
	for {
		ev, err := traceReader.ReadEvent()
		if err == io.EOF {
			break
		}
		s.Require().NoError(err)
		switch ev.Kind() {
		case xtrace.EventLog:
			logsReceived = append(logsReceived, ev)
		}
	}

	if len(s.logAssertions) == 0 {
		return
	}

	var laIdx, lrIdx int
	for ; lrIdx < len(logsReceived); lrIdx++ {
		if laIdx >= len(s.logAssertions) {
			s.Fail(fmt.Sprintf("log %q received, but no more logs were expected", logsReceived[lrIdx].Log().Message))
			continue
		}
		la := s.logAssertions[laIdx]
		laIdx++
		switch la := la.(type) {
		case logAssertion:
			lr := logsReceived[lrIdx]
			if la.msg == lr.Log().Message {
				if !la.before.IsZero() {
					s.Less(time.Unix(0, int64(lr.Time())), la.before)
				} else if !la.after.IsZero() {
					s.Greater(time.Unix(0, int64(lr.Time())), la.after)
				}
			} else if lrIdx+1 < len(logsReceived) && la.msg == logsReceived[lrIdx+1].Log().Message {
				s.Fail(fmt.Sprintf("unexpected log %q received prior to the expected log %q", lr.Log().Message, la.msg))
				laIdx--
			} else {
				s.Equal(la.msg, lr.Log().Message, "log message does not match")
			}
		case logAssertionGroup:
			// read up to len(la) logs
			logs := make([]xtrace.Event, 0, len(la.unorderedMessages))
			for j := 0; j < len(la.unorderedMessages) && lrIdx+j < len(logsReceived); j++ {
				logs = append(logs, logsReceived[lrIdx+j])
			}
			lrIdx += len(logs) - 1
			messages := []string{}
			for _, lr := range logs {
				messages = append(messages, lr.Log().Message)
				if !la.before.IsZero() {
					s.Less(time.Unix(0, int64(lr.Time())), la.before)
				} else if !la.after.IsZero() {
					s.Greater(time.Unix(0, int64(lr.Time())), la.after)
				}
			}
			s.ElementsMatch(la.unorderedMessages, messages)
		default:
			panic(fmt.Sprintf("test bug: unknown log assertion type %#T", la))
		}
	}
}

func (s *GetOrCreatePolicyEvaluatorsSuite) expectLogsF(f func() []string) {
	s.expectLogs(f()...)
}

func (s *GetOrCreatePolicyEvaluatorsSuite) expectLogsUnorderedF(f func() []string) {
	s.expectLogsUnordered(f()...)
}

func (s *GetOrCreatePolicyEvaluatorsSuite) expectLogs(msgs ...string) {
	now := time.Now()
	for _, msg := range msgs {
		s.logAssertions = append(s.logAssertions, logAssertion{
			before: now,
			msg:    msg,
		})
	}
}

func (s *GetOrCreatePolicyEvaluatorsSuite) expectLogsUnordered(msgs ...string) {
	now := time.Now()
	s.logAssertions = append(s.logAssertions, logAssertionGroup{
		before:            now,
		unorderedMessages: msgs,
	})
}

func (s *GetOrCreatePolicyEvaluatorsSuite) TestWorkers() {
	// generate 10 routes
	routes1 := s.generateRoutes(0, 10, staticPolicyFormat)
	store := store.New()
	eval, err := evaluator.New(context.Background(), store, nil, evaluator.WithPolicies(routes1))
	s.Require().NoError(err)
	s.expectLogs("using 0 cached policy evaluators")
	for _, route := range routes1 {
		rid, err := route.RouteID()
		s.NoError(err)
		s.expectLogs(fmt.Sprintf("policy for route ID %d not found in cache", rid))
	}
	s.expectLogs("chunk 0: 10/10 changed")
	s.expectLogs("chunk 0: status: 1111111111")
	s.Equal(evaluator.EvaluatorCacheStats{
		CacheHits:   0,
		CacheMisses: 10,
	}, eval.XEvaluatorCache().Stats())
	s.Equal(evaluator.QueryCacheStats{
		CacheHits:       9,
		CacheMisses:     1,
		BuildsSucceeded: 1,
		BuildsFailed:    0,
		BuildsShared:    0,
	}, eval.XQueryCache().Stats())

	// generate 10 more routes, with the first 10 cached
	routes2 := s.generateRoutes(10, 10, staticPolicyFormat)
	eval, err = evaluator.New(context.Background(), store, eval, evaluator.WithPolicies(append(routes1, routes2...)))
	s.Require().NoError(err)
	s.expectLogs("using 10 cached policy evaluators")
	for _, route := range routes2 {
		s.expectLogs(fmt.Sprintf("policy for route ID %d not found in cache", route.MustRouteID()))
	}
	s.expectLogs("chunk 0: 10/20 changed")
	s.expectLogs("chunk 0: status: 11111111110000000000")
	s.Equal(evaluator.EvaluatorCacheStats{
		CacheHits:   0 + 10,
		CacheMisses: 10 + 10,
	}, eval.XEvaluatorCache().Stats())
	s.Equal(evaluator.QueryCacheStats{
		CacheHits:       9 + 10,
		CacheMisses:     1 + 0,
		BuildsSucceeded: 1 + 0,
		BuildsFailed:    0 + 0,
		BuildsShared:    0 + 0,
	}, eval.XQueryCache().Stats())

	// generate 44 more routes, and change some existing ones around
	routes3 := s.generateRoutes(20, 44, staticPolicyFormat)
	routes1[4].AllowWebsockets = true // does not change the route id
	routes1[7].IDPClientID = "foo"    // does not change the route id
	routes1[7].IDPClientSecret = "bar"
	routes2[1].To = nil // changes the route id
	routes2[1].Redirect = &config.PolicyRedirect{
		PathRedirect: proto.String("/test"),
	}
	routes2[8].To = nil // changes the route id
	routes2[8].Response = &config.DirectResponse{
		Status: 200,
		Body:   "OK",
	}
	eval, err = evaluator.New(context.Background(), store, eval, evaluator.WithPolicies(append(append(routes1, routes2...), routes3...)))
	s.Require().NoError(err)
	s.expectLogs("using 20 cached policy evaluators")
	s.expectLogs(
		fmt.Sprintf("policy for route ID %d changed", routes1[4].MustRouteID()),
		fmt.Sprintf("policy for route ID %d changed", routes1[7].MustRouteID()),
		fmt.Sprintf("policy for route ID %d not found in cache", routes2[1].MustRouteID()),
		fmt.Sprintf("policy for route ID %d not found in cache", routes2[8].MustRouteID()),
	)
	for _, route := range routes3 {
		s.expectLogs(fmt.Sprintf("policy for route ID %d not found in cache", route.MustRouteID()))
	}
	s.expectLogs("chunk 0: 48/64 changed")
	s.expectLogs(fmt.Sprintf("chunk 0: status: %s01000000100010010000", strings.Repeat("1", 44)))
	s.Equal(evaluator.EvaluatorCacheStats{
		CacheHits:   0 + 10 + 18,
		CacheMisses: 10 + 10 + 46,
	}, eval.XEvaluatorCache().Stats())
	s.Equal(evaluator.QueryCacheStats{
		CacheHits:       9 + 10 + 48,
		CacheMisses:     1 + 0 + 0,
		BuildsSucceeded: 1 + 0 + 0,
		BuildsFailed:    0 + 0 + 0,
		BuildsShared:    0 + 0 + 0,
	}, eval.XQueryCache().Stats())

	// any additional routes should now be split into a second chunk
	routes4 := s.generateRoutes(65, 1, staticPolicyFormat)
	eval, err = evaluator.New(context.Background(), store, eval, evaluator.WithPolicies(append(append(append(routes1, routes2...), routes3...), routes4...)))
	s.Require().NoError(err)
	s.expectLogs("using 66 cached policy evaluators") // +2 because of the other policies that were modified
	for _, route := range routes4 {
		s.expectLogs(fmt.Sprintf("policy for route ID %d not found in cache", route.MustRouteID()))
	}
	s.expectLogsUnordered(
		"chunk 0: 0/64 changed",
		"chunk 1: 1/1 changed",
		"chunk 1: status: 1",
	)
	s.Equal(evaluator.EvaluatorCacheStats{
		CacheHits:   0 + 10 + 18 + 64,
		CacheMisses: 10 + 10 + 46 + 1,
	}, eval.XEvaluatorCache().Stats())
	s.Equal(evaluator.QueryCacheStats{
		CacheHits:       9 + 10 + 48 + 1,
		CacheMisses:     1 + 0 + 0 + 0,
		BuildsSucceeded: 1 + 0 + 0 + 0,
		BuildsFailed:    0 + 0 + 0 + 0,
		BuildsShared:    0 + 0 + 0 + 0,
	}, eval.XQueryCache().Stats())
}

func (s *GetOrCreatePolicyEvaluatorsSuite) TestSharedBuilds() {
	largePPL := strings.Builder{}
	largePPL.WriteString(`
allow:
  or:
`)
	for i := 0; i < 25; i++ {
		largePPL.WriteString(`
  - client_certificate:
      fingerprint: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`)
	}
	routes := s.generateRoutes(0, 650, largePPL.String())
	store := store.New()
	eval, err := evaluator.New(context.Background(), store, nil, evaluator.WithPolicies(routes))
	s.Require().NoError(err)
	s.Equal(evaluator.QueryCacheStats{
		CacheHits:       639,
		CacheMisses:     11,
		BuildsSucceeded: 1,
		BuildsFailed:    0,
		BuildsShared:    10,
	}, eval.XQueryCache().Stats())
}

func (s *GetOrCreatePolicyEvaluatorsSuite) TestPartitioning() {
	routes := s.generateRoutes(0, 64*evaluator.XWorkerPoolSize+10, uniquePerUserPolicyFormat)
	store := store.New()
	eval, err := evaluator.New(context.Background(), store, nil, evaluator.WithPolicies(routes))
	s.Require().NoError(err)
	s.Equal(evaluator.QueryCacheStats{
		CacheHits:       0,
		CacheMisses:     64*int64(evaluator.XWorkerPoolSize) + 10,
		BuildsSucceeded: 64*int64(evaluator.XWorkerPoolSize) + 10,
		BuildsFailed:    0,
		BuildsShared:    0,
	}, eval.XQueryCache().Stats())
	s.expectLogs("using 0 cached policy evaluators")

	s.expectLogsUnorderedF(func() (logs []string) {
		for _, route := range routes {
			logs = append(logs, fmt.Sprintf("policy for route ID %d not found in cache", route.MustRouteID()))
		}
		for i := range evaluator.XWorkerPoolSize {
			logs = append(logs, fmt.Sprintf("chunk %d: 64/64 changed", i))
		}
		logs = append(logs, fmt.Sprintf("chunk %d: 10/10 changed", evaluator.XWorkerPoolSize))
		return
	})
	s.expectLogsUnorderedF(func() (logs []string) {
		for i := range evaluator.XWorkerPoolSize {
			logs = append(logs, fmt.Sprintf("chunk %d: status: %s", i, strings.Repeat("1", 64)))
		}
		logs = append(logs, fmt.Sprintf("chunk %d: status: 1111111111", evaluator.XWorkerPoolSize))
		return
	})

	routes[63].AllowWebsockets = true
	eval, err = evaluator.New(context.Background(), store, eval, evaluator.WithPolicies(routes))
	s.Require().NoError(err)
	s.expectLogs(fmt.Sprintf("using %d cached policy evaluators", 64*evaluator.XWorkerPoolSize+10))
	s.expectLogsUnorderedF(func() (logs []string) {
		logs = append(logs, fmt.Sprintf("policy for route ID %d changed", routes[63].MustRouteID()))
		logs = append(logs, "chunk 0: 1/64 changed")
		for i := 1; i < evaluator.XWorkerPoolSize; i++ {
			logs = append(logs, fmt.Sprintf("chunk %d: 0/64 changed", i))
		}
		logs = append(logs, "chunk 31: 0/10 changed")
		return
	})
	s.expectLogs("chunk 0: status: 1000000000000000000000000000000000000000000000000000000000000000")

	// chunk 1 should be skipped even though it will be partitioned into worker 0
}

func TestGetOrCreatePolicyEvaluatorsSuite(t *testing.T) {
	suite.Run(t, &GetOrCreatePolicyEvaluatorsSuite{})
}
