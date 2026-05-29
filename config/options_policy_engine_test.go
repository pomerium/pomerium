package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePolicyEngine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mutate  func(o *Options)
		wantErr error
	}{
		{
			name:   "default opa is valid",
			mutate: func(*Options) {},
		},
		{
			name: "explicit opa is valid",
			mutate: func(o *Options) {
				o.PolicyEngine = PolicyEngineOPA
			},
		},
		{
			name: "external engine without flag is rejected",
			mutate: func(o *Options) {
				o.PolicyEngine = "authzen"
			},
			wantErr: ErrPolicyEngineNotPermitted,
		},
		{
			name: "external engine with flag is valid",
			mutate: func(o *Options) {
				o.PolicyEngine = "authzen"
				o.RuntimeFlags[RuntimeFlagExternalPolicyEngine] = true
			},
		},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			o := NewDefaultOptions()
			c.mutate(o)

			err := o.validatePolicyEngine()
			if c.wantErr != nil {
				assert.ErrorIs(t, err, c.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestValidateSubPolicyRego(t *testing.T) {
	t.Parallel()

	makeRoute := func(rego string) *Policy {
		return &Policy{
			From: "https://from.example.com",
			SubPolicies: []SubPolicy{{
				Rego: []string{rego},
			}},
		}
	}

	t.Run("opa permits sub-policy rego", func(t *testing.T) {
		t.Parallel()
		o := NewDefaultOptions()
		o.PolicyEngine = PolicyEngineOPA
		o.Policies = []Policy{*makeRoute("package x")}
		assert.NoError(t, o.validateSubPolicyRego())
	})

	t.Run("non-opa rejects sub-policy rego", func(t *testing.T) {
		t.Parallel()
		o := NewDefaultOptions()
		o.PolicyEngine = "authzen"
		o.Policies = []Policy{*makeRoute("package x")}
		assert.ErrorIs(t, o.validateSubPolicyRego(), ErrSubPolicyRegoNotPermitted)
	})

	t.Run("non-opa with empty rego strings is fine", func(t *testing.T) {
		t.Parallel()
		o := NewDefaultOptions()
		o.PolicyEngine = "authzen"
		o.Policies = []Policy{*makeRoute("")}
		assert.NoError(t, o.validateSubPolicyRego())
	})
}
