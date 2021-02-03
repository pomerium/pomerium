package evaluator

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestOPA(t *testing.T) {
	type A = []interface{}
	type M = map[string]interface{}

	eval := func(policies []config.Policy, data []proto.Message, req *Request, isValidClientCertificate bool) rego.Result {
		authzPolicy, err := readPolicy("/authz.rego")
		require.NoError(t, err)
		store := NewStoreFromProtos(data...)
		store.UpdateRoutePolicies(policies)
		r := rego.New(
			rego.Store(store.opaStore),
			rego.Module("pomerium.authz", string(authzPolicy)),
			rego.Query("result = data.pomerium.authz"),
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
		res := eval(nil, nil, &Request{}, false)
		assert.Equal(t,
			A{A{json.Number("495"), "invalid client certificate"}},
			res.Bindings["result"].(M)["deny"])
	})
	t.Run("email", func(t *testing.T) {
		t.Run("allowed", func(t *testing.T) {
			res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
		res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
					res := eval([]config.Policy{
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
			res := eval([]config.Policy{
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
		res := eval([]config.Policy{
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
		res := eval([]config.Policy{
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
}
