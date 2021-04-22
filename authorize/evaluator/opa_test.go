package evaluator

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestOPA(t *testing.T) {
	type A = []interface{}
	type M = map[string]interface{}

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey, jose.ES256)
	require.NoError(t, err)
	publicJWK, err := cryptutil.PublicJWKFromBytes(encodedSigningKey, jose.ES256)
	require.NoError(t, err)

	eval := func(t *testing.T, policies []config.Policy, data []proto.Message, req *Request, isValidClientCertificate bool) rego.Result {
		authzPolicy, err := readPolicy()
		require.NoError(t, err)
		store := NewStoreFromProtos(math.MaxUint64, data...)
		store.UpdateIssuer("authenticate.example.com")
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateRoutePolicies(policies)
		store.UpdateSigningKey(privateJWK)
		r := rego.New(
			rego.Store(store),
			rego.Module("pomerium.authz", string(authzPolicy)),
			rego.Query("result = data.pomerium.authz"),
			getGoogleCloudServerlessHeadersRegoOption,
			store.GetDataBrokerRecordOption(),
		)
		q, err := r.PrepareForEval(context.Background())
		require.NoError(t, err)
		rs, err := q.Eval(context.Background(),
			rego.EvalInput((&Evaluator{store: store}).newInput(req, isValidClientCertificate)),
		)
		require.NoError(t, err)
		require.Len(t, rs, 1)
		return rs[0]
	}

	t.Run("client certificate", func(t *testing.T) {
		res := eval(t, nil, nil, &Request{}, false)
		assert.Equal(t,
			A{A{json.Number("495"), "invalid client certificate"}},
			res.Bindings["result"].(M)["deny"])
	})
	t.Run("identity_headers", func(t *testing.T) {
		t.Run("kubernetes", func(t *testing.T) {
			res := eval(t, []config.Policy{{
				Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
				To: config.WeightedURLs{
					{URL: *mustParseURL("https://to.example.com")},
				},
				KubernetesServiceAccountToken: "KUBERNETES",
			}}, []proto.Message{
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
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			headers := res.Bindings["result"].(M)["identity_headers"].(M)
			assert.NotEmpty(t, headers["Authorization"])
			assert.Equal(t, "a@example.com", headers["Impersonate-User"])
			assert.Equal(t, "i1,i2", headers["Impersonate-Group"])
		})
		t.Run("google_cloud_serverless", func(t *testing.T) {
			withMockGCP(t, func() {
				res := eval(t, []config.Policy{{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					EnableGoogleCloudServerlessAuthentication: true,
				}}, []proto.Message{
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
					Session: RequestSession{
						ID: "session1",
					},
					HTTP: RequestHTTP{
						Method: "GET",
						URL:    "https://from.example.com",
					},
				}, true)
				headers := res.Bindings["result"].(M)["identity_headers"].(M)
				assert.NotEmpty(t, headers["Authorization"])
			})
		})
	})
	t.Run("jwt", func(t *testing.T) {
		evalJWT := func(msgs ...proto.Message) M {
			res := eval(t, []config.Policy{{
				Source: &config.StringURL{URL: mustParseURL("https://from.example.com:8000")},
				To: config.WeightedURLs{
					{URL: *mustParseURL("https://to.example.com")},
				},
			}}, msgs, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com:8000",
				},
			}, true)
			signedCompactJWTStr := res.Bindings["result"].(M)["signed_jwt"].(string)
			authJWT, err := jwt.ParseSigned(signedCompactJWTStr)
			require.NoError(t, err)
			var claims M
			err = authJWT.Claims(publicJWK, &claims)
			require.NoError(t, err)
			assert.LessOrEqual(t, claims["exp"], float64(time.Now().Add(time.Minute*6).Unix()),
				"JWT should expire within 5 minutes, but got: %v", claims["exp"])
			return claims
		}

		t.Run("impersonate groups", func(t *testing.T) {
			payload := evalJWT(
				&session.Session{
					Id:                "session1",
					UserId:            "user1",
					ImpersonateGroups: []string{"i1", "i2"},
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
			)
			delete(payload, "exp")
			assert.Equal(t, M{
				"aud":    "from.example.com",
				"iss":    "authenticate.example.com",
				"jti":    "session1",
				"sub":    "user1",
				"user":   "user1",
				"email":  "a@example.com",
				"groups": []interface{}{"i1", "i2"},
			}, payload)
		})
		t.Run("directory", func(t *testing.T) {
			payload := evalJWT(
				&session.Session{
					Id:        "session1",
					UserId:    "user1",
					ExpiresAt: timestamppb.New(time.Date(2021, 1, 1, 1, 1, 1, 1, time.UTC)),
					IdToken: &session.IDToken{
						IssuedAt: timestamppb.New(time.Date(2021, 2, 1, 1, 1, 1, 1, time.UTC)),
					},
					Claims: map[string]*structpb.ListValue{
						"CUSTOM_KEY": {
							Values: []*structpb.Value{
								structpb.NewStringValue("FROM_SESSION"),
							},
						},
						"email": {
							Values: []*structpb.Value{
								structpb.NewStringValue("value"),
							},
						},
					},
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
					Claims: map[string]*structpb.ListValue{
						"CUSTOM_KEY": {
							Values: []*structpb.Value{
								structpb.NewStringValue("FROM_USER"),
							},
						},
					},
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
			)
			assert.Equal(t, M{
				"aud":        "from.example.com",
				"iss":        "authenticate.example.com",
				"jti":        "session1",
				"iat":        1612141261.0,
				"exp":        1609462861.0,
				"sub":        "user1",
				"user":       "user1",
				"email":      "a@example.com",
				"groups":     A{"group1", "group1name"},
				"CUSTOM_KEY": "FROM_SESSION",
			}, payload)
		})
	})
	t.Run("email", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com:8000")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedUsers: []string{"a@example.com"},
				},
			}, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com:8000",
				},
			}, true)
			assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
		})
		t.Run("denied", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedUsers: []string{"a@example.com"},
				},
			}, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id:    "user1",
					Email: "b@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.False(t, res.Bindings["result"].(M)["allow"].(bool))
		})
	})
	t.Run("impersonate email", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedUsers: []string{"b@example.com"},
				},
			}, []proto.Message{
				&user.ServiceAccount{
					Id:               "session1",
					UserId:           "user1",
					ImpersonateEmail: proto.String("b@example.com"),
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
		})
		t.Run("denied", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedUsers: []string{"a@example.com"},
				},
			}, []proto.Message{
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
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.False(t, res.Bindings["result"].(M)["allow"].(bool))
		})
	})
	t.Run("user_id", func(t *testing.T) {
		res := eval(t, []config.Policy{
			{
				Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
				To: config.WeightedURLs{
					{URL: *mustParseURL("https://to.example.com")},
				},
				AllowedUsers: []string{"example/1234"},
			},
		}, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "example/1234",
			},
			&user.User{
				Id:    "example/1234",
				Email: "a@example.com",
			},
		}, &Request{
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method: "GET",
				URL:    "https://from.example.com",
			},
		}, true)
		assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
	})
	t.Run("domain", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedDomains: []string{"example.com"},
				},
			}, []proto.Message{
				&user.ServiceAccount{Id: "serviceaccount1"},
				&session.Session{
					Id:     "session1",
					UserId: "example/user1",
				},
				&user.User{
					Id:    "example/user1",
					Email: "a@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
		})
		t.Run("denied", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedDomains: []string{"notexample.com"},
				},
			}, []proto.Message{
				&session.Session{
					Id:     "session1",
					UserId: "user1",
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.False(t, res.Bindings["result"].(M)["allow"].(bool))
		})
	})
	t.Run("impersonate domain", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedDomains: []string{"example.com"},
				},
			}, []proto.Message{
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
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
		})
		t.Run("denied", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedDomains: []string{"example.com"},
				},
			}, []proto.Message{
				&session.Session{
					Id:               "session1",
					UserId:           "user1",
					ImpersonateEmail: proto.String("a@notexample.com"),
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.False(t, res.Bindings["result"].(M)["allow"].(bool))
		})
	})
	t.Run("groups", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			for _, nm := range []string{"group1", "group1name", "group1@example.com"} {
				t.Run(nm, func(t *testing.T) {
					res := eval(t, []config.Policy{
						{
							Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
							To: config.WeightedURLs{
								{URL: *mustParseURL("https://to.example.com")},
							},
							AllowedGroups: []string{nm},
						},
					}, []proto.Message{
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
						Session: RequestSession{
							ID: "session1",
						},
						HTTP: RequestHTTP{
							Method: "GET",
							URL:    "https://from.example.com",
						},
					}, true)
					assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
				})
			}
		})
		t.Run("denied", func(t *testing.T) {
			res := eval(t, []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
					To: config.WeightedURLs{
						{URL: *mustParseURL("https://to.example.com")},
					},
					AllowedGroups: []string{"group1"},
				},
			}, []proto.Message{
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
					GroupIds: []string{"group2"},
				},
				&directory.Group{
					Id:    "group1",
					Name:  "group-1",
					Email: "group1@example.com",
				},
			}, &Request{
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method: "GET",
					URL:    "https://from.example.com",
				},
			}, true)
			assert.False(t, res.Bindings["result"].(M)["allow"].(bool))
		})
	})
	t.Run("impersonate groups", func(t *testing.T) {
		res := eval(t, []config.Policy{
			{
				Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
				To: config.WeightedURLs{
					{URL: *mustParseURL("https://to.example.com")},
				},
				AllowedGroups: []string{"group1"},
			},
		}, []proto.Message{
			&session.Session{
				Id:                "session1",
				UserId:            "user1",
				ImpersonateEmail:  proto.String("a@example.com"),
				ImpersonateGroups: []string{"group1"},
			},
			&user.User{
				Id:    "user1",
				Email: "a@example.com",
			},
			&directory.Group{
				Id:    "group1",
				Name:  "group-1",
				Email: "group1@example.com",
			},
		}, &Request{
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method: "GET",
				URL:    "https://from.example.com",
			},
		}, true)
		assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
	})
	t.Run("any authenticated user", func(t *testing.T) {
		res := eval(t, []config.Policy{
			{
				Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
				To: config.WeightedURLs{
					{URL: *mustParseURL("https://to.example.com")},
				},
				AllowAnyAuthenticatedUser: true,
			},
		}, []proto.Message{
			&session.Session{
				Id:     "session1",
				UserId: "user1",
			},
			&user.User{
				Id:    "user1",
				Email: "a@example.com",
			},
		}, &Request{
			Session: RequestSession{
				ID: "session1",
			},
			HTTP: RequestHTTP{
				Method: "GET",
				URL:    "https://from.example.com",
			},
		}, true)
		assert.True(t, res.Bindings["result"].(M)["allow"].(bool))
	})
	t.Run("databroker versions", func(t *testing.T) {
		res := eval(t, nil, []proto.Message{
			wrapperspb.String("test"),
		}, &Request{}, false)
		serverVersion, recordVersion := getDataBrokerVersions(res.Bindings)
		assert.Equal(t, uint64(math.MaxUint64), serverVersion)
		assert.NotEqual(t, uint64(0), recordVersion) // random
	})
}
