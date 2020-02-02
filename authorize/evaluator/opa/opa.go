// Package opa implements the policy evaluator interface to make authorization
// decisions.
package opa

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

var _ evaluator.Evaluator = &PolicyEvaluator{}

// PolicyEvaluator implements the evaluator interface using the open policy
// agent framework. The Open Policy Agent (OPA, pronounced “oh-pa”) is an open
// source, general-purpose policy engine that unifies policy enforcement across
// the stack.
// https://www.openpolicyagent.org/docs/latest/
type PolicyEvaluator struct {
	// The in-memory store supports multi-reader/single-writer concurrency with
	// rollback so we leverage a RWMutex.
	mu           sync.RWMutex
	store        storage.Store
	isAuthorized rego.PreparedEvalQuery
	isAdmin      rego.PreparedEvalQuery
}

// Options represent OPA's evaluator configurations.
type Options struct {
	// AuthorizationPolicy accepts custom rego code which can be used to
	// apply custom authorization policy.
	// Defaults to authorization policy defined in config.yaml's policy.
	AuthorizationPolicy string
	// PAMPolicy accepts custom rego code which can be used to
	// apply custom privileged access management policy.
	// Defaults to users whose emails match those defined in config.yaml.
	PAMPolicy string
	// Data maps data that will be bound and
	Data map[string]interface{}
}

// New creates a new OPA policy evaluator.
func New(ctx context.Context, opts *Options) (*PolicyEvaluator, error) {
	var pe PolicyEvaluator
	pe.store = inmem.New()
	if opts.Data == nil {
		return nil, errors.New("opa: cannot create new evaluator without data")
	}
	if opts.AuthorizationPolicy == "" {
		opts.AuthorizationPolicy = defaultAuthorization
	}
	if opts.PAMPolicy == "" {
		opts.PAMPolicy = defaultPAM
	}
	if err := pe.PutData(ctx, opts.Data); err != nil {
		return nil, err
	}
	if err := pe.UpdatePolicy(ctx, opts.AuthorizationPolicy, opts.PAMPolicy); err != nil {
		return nil, err
	}
	return &pe, nil
}

// UpdatePolicy takes authorization and privilege access management rego code
// as an input and updates the prepared policy evaluator.
func (pe *PolicyEvaluator) UpdatePolicy(ctx context.Context, authz, pam string) error {
	ctx, span := trace.StartSpan(ctx, "authorize.evaluator.opa.UpdatePolicy")
	defer span.End()

	var err error
	pe.mu.Lock()
	defer pe.mu.Unlock()

	r := rego.New(
		rego.Store(pe.store),
		rego.Module("pomerium.authz", authz),
		// rego.Query("data.pomerium.authz"),
		rego.Query("result = data.pomerium.authz.allow"),
	)
	pe.isAuthorized, err = r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("opa: prepare policy: %w", err)
	}
	r = rego.New(
		rego.Store(pe.store),
		rego.Module("pomerium.pam", pam),
		rego.Query("result = data.pomerium.pam.is_admin"),
	)
	pe.isAdmin, err = r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("opa: prepare policy: %w", err)
	}
	return nil
}

// IsAuthorized determines if a given request input is authorized.
func (pe *PolicyEvaluator) IsAuthorized(ctx context.Context, input interface{}) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.evaluator.opa.PutData")
	defer span.End()
	return pe.runBoolQuery(ctx, input, pe.isAuthorized)

}

// IsAdmin determines if a given input user has super user privleges.
func (pe *PolicyEvaluator) IsAdmin(ctx context.Context, input interface{}) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.evaluator.opa.IsAdmin")
	defer span.End()
	return pe.runBoolQuery(ctx, input, pe.isAdmin)
}

// PutData adds (or replaces if the mapping key is the same) contextual data
// for making policy decisions.
func (pe *PolicyEvaluator) PutData(ctx context.Context, data map[string]interface{}) error {
	ctx, span := trace.StartSpan(ctx, "authorize.evaluator.opa.PutData")
	defer span.End()

	pe.mu.Lock()
	defer pe.mu.Unlock()
	txn, err := pe.store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("opa: bad transaction: %w", err)
	}
	if err := pe.store.Write(ctx, txn, storage.ReplaceOp, storage.Path{}, data); err != nil {
		pe.store.Abort(ctx, txn)
		return fmt.Errorf("opa: write failed %v : %w", data, err)
	}
	if err := pe.store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("opa: commit failed: %w", err)
	}
	return nil
}

func (pe *PolicyEvaluator) runBoolQuery(ctx context.Context, input interface{}, q rego.PreparedEvalQuery) (bool, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	rs, err := q.Eval(
		ctx,
		rego.EvalInput(input),
	)
	if err != nil {
		return false, fmt.Errorf("opa: eval query: %w", err)
	} else if len(rs) != 1 {
		return false, fmt.Errorf("opa: eval result set: %v, expected len 1", rs)
	} else if result, ok := rs[0].Bindings["result"].(bool); !ok {
		return false, fmt.Errorf("opa: expected bool, got: %v", rs)
	} else {
		return result, nil
	}
}
