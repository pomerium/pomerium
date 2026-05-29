package engine

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

// KindOPA is the engine kind for Pomerium's built-in OPA/Rego evaluator.
// It is the default engine.
const KindOPA Kind = "opa"

// ErrNilEvaluator is returned when the OPA factory is invoked without an
// inner *evaluator.Evaluator.
var ErrNilEvaluator = errors.New("engine: nil evaluator")

// OPAEngine is a PolicyEngine backed by the built-in OPA/Rego evaluator.
type OPAEngine struct {
	inner *evaluator.Evaluator
}

// NewOPA creates a new OPAEngine.
func NewOPA(inner *evaluator.Evaluator) (*OPAEngine, error) {
	if inner == nil {
		return nil, ErrNilEvaluator
	}
	return &OPAEngine{inner: inner}, nil
}

// Evaluate delegates to the underlying evaluator's EvaluatePolicy method.
func (e *OPAEngine) Evaluate(ctx context.Context, req *evaluator.Request) (*Decision, error) {
	pr, err := e.inner.EvaluatePolicy(ctx, req)
	if err != nil {
		return nil, err
	}
	return &Decision{
		Allow:  pr.Allow,
		Deny:   pr.Deny,
		Traces: pr.Traces,
	}, nil
}

// Close is a no-op; the underlying evaluator does not own external
// resources.
func (e *OPAEngine) Close() error {
	return nil
}

func init() {
	Register(KindOPA, false, func(cfg FactoryConfig) (PolicyEngine, error) {
		return NewOPA(cfg.OPAInner)
	})
}
