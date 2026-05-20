package authorize

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// evaluate runs the engine-aware authorize evaluation for req.
//
// It validates the client certificate once in-process — populating
// req.PrecomputedClientCertValid before any goroutines start — runs the
// policy engine and the identity-headers pipeline in parallel, and
// merges the outputs back into the shape callers expect from the legacy
// (*evaluator.Evaluator).Evaluate method.
//
// PolicyEngine implementations must not mutate req; the orchestrator is
// the only caller that does, and only before the engine sees the value.
func (a *Authorize) evaluate(ctx context.Context, req *evaluator.Request) (*evaluator.Result, error) {
	ctx, span := trace.Continue(ctx, "authorize.evaluate")
	defer span.End()

	start := time.Now()
	state := a.state.Load()

	if err := precomputeClientCertValid(state.evaluator, req); err != nil {
		return nil, err
	}

	eg, ctx := errgroup.WithContext(ctx)

	var dec *engine.Decision
	eg.Go(func() error {
		var err error
		dec, err = state.engine.Evaluate(ctx, req)
		return err
	})

	var hres *evaluator.HeadersResponse
	eg.Go(func() error {
		var err error
		hres, err = state.headers.Evaluate(ctx, req)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	evaluator.CarryOverJWTAssertion(hres.Headers, req.HTTP.Headers)

	state.evaluator.RecordMetrics(ctx, &evaluator.PolicyResponse{
		Allow:  dec.Allow,
		Deny:   dec.Deny,
		Traces: dec.Traces,
	}, time.Since(start))

	return &evaluator.Result{
		Allow:               dec.Allow,
		Deny:                dec.Deny,
		Headers:             hres.Headers,
		HeadersToRemove:     hres.HeadersToRemove,
		Traces:              dec.Traces,
		AdditionalLogFields: hres.AdditionalLogFields,
	}, nil
}

// precomputeClientCertValid validates the client certificate carried by req
// and attaches the result so that downstream evaluators see a consistent
// answer. Internal requests and requests without a route are skipped.
func precomputeClientCertValid(e *evaluator.Evaluator, req *evaluator.Request) error {
	if req == nil || req.IsInternal || req.Policy == nil {
		return nil
	}
	if req.PrecomputedClientCertValid != nil {
		return nil
	}
	v, err := e.IsValidClientCertificate(req)
	if err != nil {
		return fmt.Errorf("authorize: error validating client certificate: %w", err)
	}
	req.PrecomputedClientCertValid = &v
	return nil
}
