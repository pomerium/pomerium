package evaluator

import (
	"context"
	"net/http"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/otel/metric"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// HeadersResponse is the output from the headers.rego script.
type HeadersResponse struct {
	Headers             http.Header
	AdditionalLogFields map[log.AuthorizeLogField]any
}

// A HeadersEvaluator evaluates the headers.rego script.
type HeadersEvaluator struct {
	evaluationCount    metric.Int64Counter
	evaluationDuration metric.Int64Histogram

	store *store.Store
}

// NewHeadersEvaluator creates a new HeadersEvaluator.
func NewHeadersEvaluator(store *store.Store) *HeadersEvaluator {
	return &HeadersEvaluator{
		evaluationCount: metrics.Int64Counter("authorize.header_evaluator.evaluations",
			metric.WithDescription("Number of header evaluations."),
			metric.WithUnit("{evaluation}")),
		evaluationDuration: metrics.Int64Histogram("authorize.header_evaluator.evaluation.duration",
			metric.WithDescription("Duration of header evaluation."),
			metric.WithUnit("ms")),

		store: store,
	}
}

// Evaluate evaluates the headers.rego script.
func (e *HeadersEvaluator) Evaluate(ctx context.Context, req *Request, options ...rego.EvalOption) (*HeadersResponse, error) {
	ctx, span := trace.Continue(ctx, "authorize.HeadersEvaluator.Evaluate")
	defer span.End()

	e.evaluationCount.Add(ctx, 1)
	start := time.Now()

	ectx := new(rego.EvalContext)
	for _, option := range options {
		option(ectx)
	}
	now := ectx.Time()
	if now.IsZero() {
		now = time.Now()
	}
	res, err := newHeadersEvaluatorEvaluation(e, req, now).execute(ctx)
	e.evaluationDuration.Record(ctx, time.Since(start).Milliseconds())
	return res, err
}
