package evaluator

import (
	"context"
	"net/http"
	"time"

	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// HeadersResponse is the output from the headers.rego script.
type HeadersResponse struct {
	Headers http.Header
}

// A HeadersEvaluator evaluates the headers.rego script.
type HeadersEvaluator struct {
	store *store.Store
}

// NewHeadersEvaluator creates a new HeadersEvaluator.
func NewHeadersEvaluator(store *store.Store) *HeadersEvaluator {
	return &HeadersEvaluator{
		store: store,
	}
}

// Evaluate evaluates the headers.rego script.
func (e *HeadersEvaluator) Evaluate(ctx context.Context, req *Request, options ...rego.EvalOption) (*HeadersResponse, error) {
	ctx, span := trace.Continue(ctx, "authorize.HeadersEvaluator.Evaluate")
	defer span.End()

	ectx := new(rego.EvalContext)
	for _, option := range options {
		option(ectx)
	}
	now := ectx.Time()
	if now.IsZero() {
		now = time.Now()
	}
	return newHeadersEvaluatorEvaluation(e, req, now).execute(ctx)
}
