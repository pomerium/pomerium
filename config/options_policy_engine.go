package config

import (
	"errors"
	"fmt"
)

// PolicyEngineOPA is the default engine name; it selects Pomerium's
// built-in OPA/Rego evaluator.
const PolicyEngineOPA = "opa"

// Sentinel errors returned by policy-engine validation.
//
// Per-engine config validity (unknown kind, malformed
// external_policy_engine block) is surfaced later, at authorize-state
// construction time, by the engine package's factory. The config layer
// only performs static checks here to avoid an import cycle with
// authorize/evaluator/engine.
var (
	ErrPolicyEngineNotPermitted  = errors.New("config: external policy engines require the external_policy_engine runtime flag")
	ErrSubPolicyRegoNotPermitted = errors.New("config: sub_policies[].rego is only supported with policy_engine=opa")
)

// validatePolicyEngine validates the policy engine selection on Options.
// It is called from (*Options).Validate.
//
// The runtime-flag gate is enforced here so that a configuration
// selecting a non-OPA engine without the external_policy_engine flag
// fails fast at startup.
func (o *Options) validatePolicyEngine() error {
	if o.PolicyEngine == "" || o.PolicyEngine == PolicyEngineOPA {
		return nil
	}
	if !o.IsRuntimeFlagSet(RuntimeFlagExternalPolicyEngine) {
		return fmt.Errorf("%w (kind=%q)", ErrPolicyEngineNotPermitted, o.PolicyEngine)
	}
	return nil
}

// validateSubPolicyRego ensures custom Rego sub-policies are only used
// with the OPA engine. Other engines cannot evaluate Rego.
func (o *Options) validateSubPolicyRego() error {
	if o.PolicyEngine == "" || o.PolicyEngine == PolicyEngineOPA {
		return nil
	}
	for p := range o.GetAllPolicies() {
		for _, sp := range p.SubPolicies {
			for _, r := range sp.Rego {
				if r == "" {
					continue
				}
				return fmt.Errorf("%w (route from=%q)", ErrSubPolicyRegoNotPermitted, p.From)
			}
		}
	}
	return nil
}
