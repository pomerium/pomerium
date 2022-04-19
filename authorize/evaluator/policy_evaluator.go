package evaluator

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	octrace "go.opencensus.io/trace"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// PolicyRequest is the input to policy evaluation.
type PolicyRequest struct {
	HTTP                     RequestHTTP    `json:"http"`
	Session                  RequestSession `json:"session"`
	IsValidClientCertificate bool           `json:"is_valid_client_certificate"`
}

// PolicyResponse is the result of evaluating a policy.
type PolicyResponse struct {
	Allow, Deny RuleResult
}

// NewPolicyResponse creates a new PolicyResponse.
func NewPolicyResponse() *PolicyResponse {
	return &PolicyResponse{
		Allow: NewRuleResult(false),
		Deny:  NewRuleResult(false),
	}
}

// A RuleResult is the result of evaluating a rule.
type RuleResult struct {
	Value          bool
	Reasons        criteria.Reasons
	AdditionalData map[string]interface{}
}

// NewRuleResult creates a new RuleResult.
func NewRuleResult(value bool, reasons ...criteria.Reason) RuleResult {
	return RuleResult{
		Value:          value,
		Reasons:        criteria.NewReasons(reasons...),
		AdditionalData: map[string]interface{}{},
	}
}

// MergeRuleResultsWithOr merges all the results using `or`.
func MergeRuleResultsWithOr(results ...RuleResult) RuleResult {
	merged := NewRuleResult(false)

	var trueResults, falseResults []RuleResult
	for _, result := range results {
		if result.Value {
			trueResults = append(trueResults, result)
		} else {
			falseResults = append(falseResults, result)
		}
	}

	if len(trueResults) > 0 {
		merged.Value = true
		for _, result := range trueResults {
			merged.Reasons = merged.Reasons.Union(result.Reasons)
			for k, v := range result.AdditionalData {
				merged.AdditionalData[k] = v
			}
		}
	} else {
		merged.Value = false
		for _, result := range falseResults {
			merged.Reasons = merged.Reasons.Union(result.Reasons)
			for k, v := range result.AdditionalData {
				merged.AdditionalData[k] = v
			}
		}
	}

	return merged
}

type policyQuery struct {
	rego.PreparedEvalQuery
	checksum string
}

// A PolicyEvaluator evaluates policies.
type PolicyEvaluator struct {
	queries []policyQuery
}

// NewPolicyEvaluator creates a new PolicyEvaluator.
func NewPolicyEvaluator(ctx context.Context, store *store.Store, configPolicy *config.Policy) (*PolicyEvaluator, error) {
	e := new(PolicyEvaluator)

	// generate the base rego script for the policy
	ppl := configPolicy.ToPPL()
	base, err := policy.GenerateRegoFromPolicy(ppl)
	if err != nil {
		return nil, err
	}

	scripts := []string{base}

	// add any custom rego
	for _, sp := range configPolicy.SubPolicies {
		for _, src := range sp.Rego {
			if src == "" {
				continue
			}

			scripts = append(scripts, src)
		}
	}

	// for each script, create a rego and prepare a query.
	for _, script := range scripts {
		log.Debug(ctx).
			Str("script", script).
			Str("from", configPolicy.From).
			Interface("to", configPolicy.To).
			Msg("authorize: rego script for policy evaluation")

		r := rego.New(
			rego.Store(store),
			rego.Module("pomerium.policy", script),
			rego.Query("result = data.pomerium.policy"),
			getGoogleCloudServerlessHeadersRegoOption,
			store.GetDataBrokerRecordOption(),
		)

		q, err := r.PrepareForEval(ctx)
		// if no package is in the src, add it
		if err != nil && strings.Contains(err.Error(), "package expected") {
			r := rego.New(
				rego.Store(store),
				rego.Module("pomerium.policy", "package pomerium.policy\n\n"+script),
				rego.Query("result = data.pomerium.policy"),
				getGoogleCloudServerlessHeadersRegoOption,
				store.GetDataBrokerRecordOption(),
			)
			q, err = r.PrepareForEval(ctx)
		}
		if err != nil {
			return nil, err
		}

		e.queries = append(e.queries, policyQuery{
			PreparedEvalQuery: q,
			checksum:          fmt.Sprintf("%x", cryptutil.Hash("script", []byte(script))),
		})
	}

	return e, nil
}

// Evaluate evaluates the policy rego scripts.
func (e *PolicyEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyResponse, error) {
	res := NewPolicyResponse()
	// run each query and merge the results
	for _, query := range e.queries {
		o, err := e.evaluateQuery(ctx, req, query)
		if err != nil {
			return nil, err
		}
		res.Allow = MergeRuleResultsWithOr(res.Allow, o.Allow)
		res.Deny = MergeRuleResultsWithOr(res.Deny, o.Deny)
	}
	return res, nil
}

func (e *PolicyEvaluator) evaluateQuery(ctx context.Context, req *PolicyRequest, query policyQuery) (*PolicyResponse, error) {
	_, span := trace.StartSpan(ctx, "authorize.PolicyEvaluator.evaluateQuery")
	defer span.End()
	span.AddAttributes(octrace.StringAttribute("script_checksum", query.checksum))

	rs, err := safeEval(ctx, query.PreparedEvalQuery, rego.EvalInput(req))
	if err != nil {
		return nil, fmt.Errorf("authorize: error evaluating policy.rego: %w", err)
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("authorize: unexpected empty result from evaluating policy.rego")
	}

	res := &PolicyResponse{
		Allow: e.getRuleResult("allow", rs[0].Bindings),
		Deny:  e.getRuleResult("deny", rs[0].Bindings),
	}
	return res, nil
}

// getRuleResult gets the rule result var. It expects a boolean, [boolean, []string] or [boolean, []string, object].
func (e *PolicyEvaluator) getRuleResult(name string, vars rego.Vars) (result RuleResult) {
	result = NewRuleResult(false)

	m, ok := vars["result"].(map[string]interface{})
	if !ok {
		return result
	}

	switch t := m[name].(type) {
	case bool:
		result.Value = t
	case []interface{}:
		switch len(t) {
		case 3:
			v, ok := t[2].(map[string]interface{})
			if ok {
				for k, vv := range v {
					result.AdditionalData[k] = vv
				}
			}
			fallthrough
		case 2:
			// fill in the reasons
			v, ok := t[1].([]interface{})
			if ok {
				for _, vv := range v {
					result.Reasons.Add(criteria.Reason(fmt.Sprint(vv)))
				}
			}
			fallthrough
		case 1:
			// fill in the value
			v, ok := t[0].(bool)
			if !ok {
				return result
			}
			result.Value = v
		}
	}

	return result
}
