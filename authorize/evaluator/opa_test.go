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
		assert.Equal(t, rego.Vars{
			"result": M{
				"allow": false,
				"deny":  A{A{json.Number("495"), "invalid client certificate"}},
			},
		}, res.Bindings)
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
}
