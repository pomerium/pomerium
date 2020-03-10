//go:generate statik -src=./policy -include=*.rego -ns rego -p policy

// Package opa implements the policy evaluator interface to make authorization
// decisions.
package opa

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/rakyll/statik/fs"

	"github.com/pomerium/pomerium/authorize/evaluator"
	_ "github.com/pomerium/pomerium/authorize/evaluator/opa/policy" // load static assets
	pb "github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

const statikNamespace = "rego"

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
}

// Options represent OPA's evaluator configurations.
type Options struct {
	// AuthorizationPolicy accepts custom rego code which can be used to
	// apply custom authorization policy.
	// Defaults to authorization policy defined in config.yaml's policy.
	AuthorizationPolicy string
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
		b, err := readPolicy("/authz.rego")
		if err != nil {
			return nil, err
		}
		opts.AuthorizationPolicy = string(b)
	}
	if err := pe.PutData(ctx, opts.Data); err != nil {
		return nil, err
	}
	if err := pe.UpdatePolicy(ctx, opts.AuthorizationPolicy); err != nil {
		return nil, err
	}
	return &pe, nil
}

// UpdatePolicy takes authorization and privilege access management rego code
// as an input and updates the prepared policy evaluator.
func (pe *PolicyEvaluator) UpdatePolicy(ctx context.Context, authz string) error {
	ctx, span := trace.StartSpan(ctx, "authorize.evaluator.opa.UpdatePolicy")
	defer span.End()

	var err error
	pe.mu.Lock()
	defer pe.mu.Unlock()

	r := rego.New(
		rego.Store(pe.store),
		rego.Module("pomerium.authz", authz),
		rego.Query("result = data.pomerium.authz"),
	)
	pe.isAuthorized, err = r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("opa: prepare policy: %w", err)
	}
	return nil
}

// IsAuthorized determines if a given request input is authorized.
func (pe *PolicyEvaluator) IsAuthorized(ctx context.Context, input interface{}) (*pb.IsAuthorizedReply, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.evaluator.opa.IsAuthorized")
	defer span.End()
	return pe.runBoolQuery(ctx, input, pe.isAuthorized)
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

func decisionFromInterface(i interface{}) (*pb.IsAuthorizedReply, error) {
	var d pb.IsAuthorizedReply
	var ok bool
	m, ok := i.(map[string]interface{})
	if !ok {
		return nil, errors.New("interface must be a map")
	}
	if d.Allow, ok = m["allow"].(bool); !ok {
		return nil, errors.New("allow should be bool")
	}
	if d.SessionExpired, ok = m["expired"].(bool); !ok {
		return nil, errors.New("expired should be bool")
	}

	switch v := m["deny"].(type) {
	case []interface{}:
		for _, cause := range v {
			if c, ok := cause.(string); ok {
				d.DenyReasons = append(d.DenyReasons, c)
			}
		}
	case string:
		d.DenyReasons = []string{v}
	}

	if v, ok := m["user"].(string); ok {
		d.User = v
	}

	if v, ok := m["email"].(string); ok {
		d.Email = v
	}

	switch v := m["groups"].(type) {
	case []interface{}:
		for _, cause := range v {
			if c, ok := cause.(string); ok {
				d.Groups = append(d.Groups, c)
			}
		}
	case string:
		d.Groups = []string{v}
	}

	if v, ok := m["signed_jwt"].(string); ok {
		d.SignedJwt = v
	}
	return &d, nil
}

func (pe *PolicyEvaluator) runBoolQuery(ctx context.Context, input interface{}, q rego.PreparedEvalQuery) (*pb.IsAuthorizedReply, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("eval query: %w", err)
	} else if len(rs) == 0 {
		return nil, fmt.Errorf("empty eval result set %v", rs)
	}
	bindings := rs[0].Bindings.WithoutWildcards()["result"]
	return decisionFromInterface(bindings)
}

func readPolicy(fn string) ([]byte, error) {
	statikFS, err := fs.NewWithNamespace(statikNamespace)
	if err != nil {
		return nil, err
	}
	r, err := statikFS.Open(fn)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}
