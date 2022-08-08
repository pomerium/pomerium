package contextutil

import "context"

// A PolicyEvaluationTrace traces a policy evaluation.
type PolicyEvaluationTrace struct {
	ID          string `json:"id"`
	Explanation string `json:"explanation"`
	Remediation string `json:"remediation"`
	Allow       bool   `json:"allow"`
	Deny        bool   `json:"deny"`
}

type policyEvaluationTraceKey struct{}

// GetPolicyEvaluationTraces gets the policy evaluation traces from a context.
func GetPolicyEvaluationTraces(ctx context.Context) []PolicyEvaluationTrace {
	v, _ := ctx.Value(policyEvaluationTraceKey{}).([]PolicyEvaluationTrace)
	return v
}

// WithPolicyEvaluationTraces attaches policy evaluation traces to a context.
func WithPolicyEvaluationTraces(ctx context.Context, traces []PolicyEvaluationTrace) context.Context {
	return context.WithValue(ctx, policyEvaluationTraceKey{}, traces)
}
