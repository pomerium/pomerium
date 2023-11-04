package authorize

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

func TestNew(t *testing.T) {
	t.Parallel()
	policies := testPolicies(t)
	tests := []struct {
		name    string
		config  config.Options
		wantErr bool
	}{
		{
			"good",
			config.Options{
				AuthenticateURLString: "https://authN.example.com",
				DataBrokerURLString:   "https://databroker.example.com",
				SharedKey:             "2p/Wi2Q6bYDfzmoSEbKqYKtg+DUoLWTEHHs7vOhvL7w=",
				Policies:              policies,
			},
			false,
		},
		{
			"bad shared secret",
			config.Options{
				AuthenticateURLString: "https://authN.example.com",
				DataBrokerURLString:   "https://databroker.example.com",
				SharedKey:             "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==",
				Policies:              policies,
			},
			true,
		},
		{
			"really bad shared secret",
			config.Options{
				AuthenticateURLString: "https://authN.example.com",
				DataBrokerURLString:   "https://databroker.example.com",
				SharedKey:             "sup",
				Policies:              policies,
			},
			true,
		},
		{
			"validation error, short secret",
			config.Options{
				AuthenticateURLString: "https://authN.example.com",
				DataBrokerURLString:   "https://databroker.example.com",
				SharedKey:             "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==",
				Policies:              policies,
			},
			true,
		},
		{"empty options", config.Options{}, true},
		{
			"bad databroker url",
			config.Options{
				AuthenticateURLString: "https://authN.example.com",
				DataBrokerURLString:   "BAD",
				SharedKey:             "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==",
				Policies:              policies,
			},
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(&config.Config{Options: &tt.config})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAuthorize_OnConfigChange(t *testing.T) {
	t.Parallel()
	policies := testPolicies(t)
	tests := []struct {
		name           string
		SharedKey      string
		Policies       []config.Policy
		expectedChange bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, true},
		{"bad option", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := &config.Options{
				AuthenticateURLString: "https://authN.example.com",
				DataBrokerURLString:   "https://databroker.example.com",
				SharedKey:             tc.SharedKey,
				Policies:              tc.Policies,
			}
			a, err := New(&config.Config{Options: o})
			require.NoError(t, err)
			require.NotNil(t, a)

			oldPe := a.state.Load().evaluator
			cfg := &config.Config{Options: o}
			assertFunc := assert.True
			o.SigningKey = "bad-share-key"
			if tc.expectedChange {
				o.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUhHNHZDWlJxUFgwNGtmSFQxeVVDM1pUQkF6MFRYWkNtZ043clpDcFE3cHJvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFbzQzdjAwQlR4c3pKZWpmdHhBOWNtVGVUSmtQQXVtOGt1b0UwVlRUZnlId2k3SHJlN2FRUgpHQVJ6Nm0wMjVRdGFiRGxqeDd5MjIyY1gxblhCQXo3MlF3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
				assertFunc = assert.False
			}
			a.OnConfigChange(context.Background(), cfg)
			assertFunc(t, oldPe == a.state.Load().evaluator)
		})
	}
}

func testPolicies(t *testing.T) []config.Policy {
	testPolicy := config.Policy{
		From:         "https://pomerium.io",
		To:           mustParseWeightedURLs(t, "http://httpbin.org"),
		AllowedUsers: []string{"test@gmail.com"},
	}
	err := testPolicy.Validate()
	if err != nil {
		t.Fatal(err)
	}
	policies := []config.Policy{
		testPolicy,
	}
	return policies
}

func TestNewPolicyEvaluator_addDefaultClientCertificateRule(t *testing.T) {
	t.Parallel()

	resultFalse := evaluator.NewRuleResult(false) // no mention of client certificates
	resultClientCertificateRequired := evaluator.NewRuleResult(true,
		criteria.ReasonClientCertificateRequired)

	cases := []struct {
		label    string
		opts     *config.Options
		expected evaluator.RuleResult
	}{
		{"zero", &config.Options{}, resultFalse},
		{"default", config.NewDefaultOptions(), resultFalse},
		{"client CA, default enforcement", &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{CA: "ZmFrZSBDQQ=="},
		}, resultClientCertificateRequired},
		{"client CA, reject connection", &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA:          "ZmFrZSBDQQ==",
				Enforcement: config.MTLSEnforcementRejectConnection,
			},
		}, resultClientCertificateRequired},
		{"client CA, policy", &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA:          "ZmFrZSBDQQ==",
				Enforcement: config.MTLSEnforcementPolicy,
			},
		}, resultFalse},
	}
	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			store := store.New()
			c.opts.Policies = []config.Policy{{
				To: mustParseWeightedURLs(t, "http://example.com"),
			}}
			e, err := newPolicyEvaluator(c.opts, store, nil)
			require.NoError(t, err)

			r, err := e.Evaluate(context.Background(), &evaluator.Request{
				Policy: &c.opts.Policies[0],
				HTTP:   evaluator.RequestHTTP{},
			})
			require.NoError(t, err)
			assert.Equal(t, c.expected, r.Deny)
		})
	}
}
