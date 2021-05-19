package evaluator

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/policy"
)

// PolicyRequest is the input to policy evaluation.
type PolicyRequest struct {
	HTTP                     RequestHTTP    `json:"http"`
	Session                  RequestSession `json:"session"`
	IsValidClientCertificate bool           `json:"is_valid_client_certificate"`
}

// PolicyResponse is the result of evaluating a policy.
type PolicyResponse struct {
	Allow bool
	Deny  *Denial
}

// Merge merges another PolicyResponse into this PolicyResponse. Access is allowed if either is allowed. Access is denied if
// either is denied. (and denials take precedence)
func (res *PolicyResponse) Merge(other *PolicyResponse) *PolicyResponse {
	merged := &PolicyResponse{
		Allow: res.Allow || other.Allow,
		Deny:  res.Deny,
	}
	if other.Deny != nil {
		merged.Deny = other.Deny
	}
	return merged
}

// A Denial indicates the request should be denied (even if otherwise allowed).
type Denial struct {
	Status  int
	Message string
}

// A PolicyEvaluator evaluates policies.
type PolicyEvaluator struct {
	queries []rego.PreparedEvalQuery
}

// NewPolicyEvaluator creates a new PolicyEvaluator.
func NewPolicyEvaluator(ctx context.Context, store *Store, configPolicy *config.Policy) (*PolicyEvaluator, error) {
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
		e.queries = append(e.queries, q)
	}

	return e, nil
}

// Evaluate evaluates the policy rego scripts.
func (e *PolicyEvaluator) Evaluate(ctx context.Context, req *PolicyRequest) (*PolicyResponse, error) {
	res := new(PolicyResponse)
	// run each query and merge the results
	for _, query := range e.queries {
		o, err := e.evaluateQuery(ctx, req, query)
		if err != nil {
			return nil, err
		}
		res = res.Merge(o)
	}
	return res, nil
}

func (e *PolicyEvaluator) evaluateQuery(ctx context.Context, req *PolicyRequest, query rego.PreparedEvalQuery) (*PolicyResponse, error) {
	rs, err := query.Eval(ctx, rego.EvalInput(req))
	if err != nil {
		return nil, fmt.Errorf("authorize: error evaluating policy.rego: %w", err)
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("authorize: unexpected empty result from evaluating policy.rego")
	}

	res := &PolicyResponse{
		Allow: e.getAllow(rs[0].Bindings),
		Deny:  e.getDeny(ctx, rs[0].Bindings),
	}
	return res, nil
}

// getAllow gets the allow var. It expects a boolean.
func (e *PolicyEvaluator) getAllow(vars rego.Vars) bool {
	m, ok := vars["result"].(map[string]interface{})
	if !ok {
		return false
	}

	allow, ok := m["allow"].(bool)
	if !ok {
		return false
	}

	return allow
}

// getDeny gets the deny var. It expects an (http status code, message) pair.
func (e *PolicyEvaluator) getDeny(ctx context.Context, vars rego.Vars) *Denial {
	m, ok := vars["result"].(map[string]interface{})
	if !ok {
		return nil
	}

	pair, ok := m["deny"].([]interface{})
	if !ok {
		return nil
	}

	status, err := strconv.Atoi(fmt.Sprint(pair[0]))
	if err != nil {
		log.Error(ctx).Err(err).Msg("invalid type in deny")
		return nil
	}
	msg := fmt.Sprint(pair[1])

	return &Denial{
		Status:  status,
		Message: msg,
	}
}
