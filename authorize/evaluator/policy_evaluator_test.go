package evaluator

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/policy/input"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestPolicyEvaluator(t *testing.T) {
	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey)
	require.NoError(t, err)

	var addDefaultClientCertificateRule bool

	eval := func(t *testing.T, policy *config.Policy, data []proto.Message, input *input.PolicyRequest) (*PolicyResponse, error) {
		ctx := context.Background()
		ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier(data...))
		store := store.New()
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := NewPolicyEvaluator(ctx, store, policy, addDefaultClientCertificateRule)
		require.NoError(t, err)
		return e.Evaluate(ctx, input)
	}

	p1 := &config.Policy{
		From:         "https://from.example.com",
		To:           config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
		AllowedUsers: []string{"u1@example.com"},
	}
	s1 := &session.Session{
		Id:     "s1",
		UserId: "u1",
	}
	s2 := &session.Session{
		Id:     "s2",
		UserId: "u2",
	}
	u1 := &user.User{
		Id:    "u1",
		Email: "u1@example.com",
	}
	u2 := &user.User{
		Id:    "u2",
		Email: "u2@example.com",
	}

	t.Run("allowed", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "s1"},
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:   NewRuleResult(false),
			Traces: []contextutil.PolicyEvaluationTrace{{Allow: true}},
		}, output)
	})
	t.Run("forbidden", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "s2"},
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(false, criteria.ReasonEmailUnauthorized, criteria.ReasonUserUnauthorized),
			Deny:   NewRuleResult(false),
			Traces: []contextutil.PolicyEvaluationTrace{{}},
		}, output)
	})

	// Enable client certificate validation.
	addDefaultClientCertificateRule = true

	t.Run("allowed with cert", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "s1"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:   NewRuleResult(false, criteria.ReasonValidClientCertificate),
			Traces: []contextutil.PolicyEvaluationTrace{{Allow: true}},
		}, output)
	})
	t.Run("no cert", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "s1"},

				IsValidClientCertificate: false,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:   NewRuleResult(true, criteria.ReasonClientCertificateRequired),
			Traces: []contextutil.PolicyEvaluationTrace{{Allow: true, Deny: true}},
		}, output)
	})
	t.Run("invalid cert", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&input.PolicyRequest{
				HTTP: input.RequestHTTP{
					Method:            http.MethodGet,
					URL:               "https://from.example.com/path",
					ClientCertificate: input.ClientCertificateInfo{Presented: true},
				},
				Session: input.RequestSession{ID: "s1"},

				IsValidClientCertificate: false,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:   NewRuleResult(true, criteria.ReasonInvalidClientCertificate),
			Traces: []contextutil.PolicyEvaluationTrace{{Allow: true, Deny: true}},
		}, output)
	})
	t.Run("forbidden with cert", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{s1, u1, s2, u2},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "s2"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(false, criteria.ReasonEmailUnauthorized, criteria.ReasonUserUnauthorized),
			Deny:   NewRuleResult(false, criteria.ReasonValidClientCertificate),
			Traces: []contextutil.PolicyEvaluationTrace{{}},
		}, output)
	})

	t.Run("ppl", func(t *testing.T) {
		t.Run("allow", func(t *testing.T) {
			rego, err := policy.GenerateRegoFromReader(strings.NewReader(`
- allow:
    and:
      - accept: 1
`))
			require.NoError(t, err)
			p := &config.Policy{
				From: "https://from.example.com",
				To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				SubPolicies: []config.SubPolicy{
					{ID: "p1", Rego: []string{rego}},
				},
			}
			output, err := eval(t,
				p,
				[]proto.Message{s1, u1, s2, u2},
				&input.PolicyRequest{
					HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
					Session: input.RequestSession{ID: "s1"},

					IsValidClientCertificate: true,
				})
			require.NoError(t, err)
			assert.Equal(t, &PolicyResponse{
				Allow:  NewRuleResult(true, criteria.ReasonAccept),
				Deny:   NewRuleResult(false, criteria.ReasonValidClientCertificate),
				Traces: []contextutil.PolicyEvaluationTrace{{}, {ID: "p1", Allow: true}},
			}, output)
		})
		t.Run("deny", func(t *testing.T) {
			rego, err := policy.GenerateRegoFromReader(strings.NewReader(`
- deny:
    and:
      - accept: 1
`))
			require.NoError(t, err)
			p := &config.Policy{
				From: "https://from.example.com",
				To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				SubPolicies: []config.SubPolicy{
					{ID: "p1", Rego: []string{rego}},
				},
			}
			output, err := eval(t,
				p,
				[]proto.Message{s1, u1, s2, u2},
				&input.PolicyRequest{
					HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
					Session: input.RequestSession{ID: "s1"},

					IsValidClientCertificate: true,
				})
			require.NoError(t, err)
			assert.Equal(t, &PolicyResponse{
				Allow:  NewRuleResult(false),
				Deny:   NewRuleResult(true, criteria.ReasonAccept),
				Traces: []contextutil.PolicyEvaluationTrace{{}, {ID: "p1", Deny: true}},
			}, output)
		})
		t.Run("client certificate", func(t *testing.T) {
			rego, err := policy.GenerateRegoFromReader(strings.NewReader(`
- deny:
    and:
      - invalid_client_certificate: 1
      - accept: 1
`))
			require.NoError(t, err)
			p := &config.Policy{
				From: "https://from.example.com",
				To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				SubPolicies: []config.SubPolicy{
					{ID: "p1", Rego: []string{rego}},
				},
			}
			output, err := eval(t,
				p,
				[]proto.Message{s1, u1, s2, u2},
				&input.PolicyRequest{
					HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
					Session: input.RequestSession{ID: "s1"},

					IsValidClientCertificate: false,
				})
			require.NoError(t, err)
			assert.Equal(t, &PolicyResponse{
				Allow:  NewRuleResult(false),
				Deny:   NewRuleResult(true, criteria.ReasonAccept, criteria.ReasonClientCertificateRequired),
				Traces: []contextutil.PolicyEvaluationTrace{{Deny: true}, {ID: "p1", Deny: true}},
			}, output)
		})
	})
	t.Run("cidr", func(t *testing.T) {
		r1 := &structpb.Struct{Fields: map[string]*structpb.Value{
			"$index": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("192.168.0.0/16"),
			}}),
			"country": structpb.NewStringValue("US"),
		}}

		p := &config.Policy{
			From: "https://from.example.com",
			To:   config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
			SubPolicies: []config.SubPolicy{
				{ID: "p1", Rego: []string{`
					package pomerium.policy

					allow {
						record := get_databroker_record("type.googleapis.com/google.protobuf.Struct", "192.168.0.7")
						record.country == "US"
					}
				`}},
			},
		}
		output, err := eval(t,
			p,
			[]proto.Message{s1, u1, s2, u2, r1},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "s1"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(true),
			Deny:   NewRuleResult(false, criteria.ReasonValidClientCertificate),
			Traces: []contextutil.PolicyEvaluationTrace{{}, {ID: "p1", Allow: true}},
		}, output)
	})
	t.Run("service account", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{
				u1,
				&user.ServiceAccount{
					Id:     "sa1",
					UserId: "u1",
				},
			},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "sa1"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(true, criteria.ReasonEmailOK),
			Deny:   NewRuleResult(false, criteria.ReasonValidClientCertificate),
			Traces: []contextutil.PolicyEvaluationTrace{{Allow: true}},
		}, output)
	})
	t.Run("expired service account", func(t *testing.T) {
		output, err := eval(t,
			p1,
			[]proto.Message{
				u1,
				&user.ServiceAccount{
					Id:        "sa1",
					UserId:    "u1",
					ExpiresAt: timestamppb.New(time.Now().Add(-time.Second)),
				},
			},
			&input.PolicyRequest{
				HTTP:    input.RequestHTTP{Method: http.MethodGet, URL: "https://from.example.com/path"},
				Session: input.RequestSession{ID: "sa1"},

				IsValidClientCertificate: true,
			})
		require.NoError(t, err)
		assert.Equal(t, &PolicyResponse{
			Allow:  NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			Deny:   NewRuleResult(false, criteria.ReasonValidClientCertificate),
			Traces: []contextutil.PolicyEvaluationTrace{{Allow: false}},
		}, output)
	})
}
