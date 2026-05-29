// Package engine defines a pluggable policy-engine abstraction for the
// authorize service.
package engine

import (
	"context"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/pkg/contextutil"
)

// A PolicyEngine evaluates the access-decision portion of an authorize
// request. Identity headers are produced separately by HeadersEvaluator and
// are not the engine's concern.
//
// Implementations must be safe for concurrent use and must honor ctx
// cancellation.
type PolicyEngine interface {
	Evaluate(ctx context.Context, req *evaluator.Request) (*Decision, error)
	Close() error
}

// A Decision is the access-decision portion of an evaluator.Result.
type Decision struct {
	Allow  evaluator.RuleResult
	Deny   evaluator.RuleResult
	Traces []contextutil.PolicyEvaluationTrace
}
