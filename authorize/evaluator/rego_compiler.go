package evaluator

import (
	"context"
	"fmt"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/authorize/evaluator/opa"
	"github.com/pomerium/pomerium/authorize/internal/store"
)

// A RegoCompiler compiles rego scripts.
type RegoCompiler struct {
	Store        *store.Store
	policyCache  *lru.Cache[string, rego.PreparedEvalQuery]
	headersCache *lru.Cache[string, rego.PreparedEvalQuery]
}

// NewRegoCompiler creates a new RegoCompiler using the given store.
func NewRegoCompiler(store *store.Store) *RegoCompiler {
	policyCache, err := lru.New[string, rego.PreparedEvalQuery](10_000)
	if err != nil {
		panic(fmt.Errorf("failed to create lru cache for policy rego scripts: %w", err))
	}
	headersCache, err := lru.New[string, rego.PreparedEvalQuery](1)
	if err != nil {
		panic(fmt.Errorf("failed to create lru cache for headers rego scripts: %w", err))
	}
	return &RegoCompiler{
		Store:        store,
		policyCache:  policyCache,
		headersCache: headersCache,
	}
}

// CompileHeadersQuery compiles a headers query.
func (rc *RegoCompiler) CompileHeadersQuery(
	ctx context.Context,
	script string,
) (rego.PreparedEvalQuery, error) {
	if q, ok := rc.headersCache.Get(script); ok {
		return q, nil
	}

	r := rego.New(
		rego.Store(rc.Store),
		rego.Module("pomerium.headers", opa.HeadersRego),
		rego.Query("result = data.pomerium.headers"),
		getGoogleCloudServerlessHeadersRegoOption,
		variableSubstitutionFunctionRegoOption,
		rc.Store.GetDataBrokerRecordOption(),
	)
	q, err := r.PrepareForEval(ctx)
	if err != nil {
		return q, err
	}

	rc.headersCache.Add(script, q)
	return q, nil
}

// CompilePolicyQuery compiles a policy query.
func (rc *RegoCompiler) CompilePolicyQuery(
	ctx context.Context,
	script string,
) (rego.PreparedEvalQuery, error) {
	if q, ok := rc.policyCache.Get(script); ok {
		return q, nil
	}

	r := rego.New(
		rego.Store(rc.Store),
		rego.Module("pomerium.policy", script),
		rego.Query("result = data.pomerium.policy"),
		getGoogleCloudServerlessHeadersRegoOption,
		rc.Store.GetDataBrokerRecordOption(),
	)

	q, err := r.PrepareForEval(ctx)
	// if no package is in the src, add it
	if err != nil && strings.Contains(err.Error(), "package expected") {
		r := rego.New(
			rego.Store(rc.Store),
			rego.Module("pomerium.policy", "package pomerium.policy\n\n"+script),
			rego.Query("result = data.pomerium.policy"),
			getGoogleCloudServerlessHeadersRegoOption,
			rc.Store.GetDataBrokerRecordOption(),
		)
		q, err = r.PrepareForEval(ctx)
	}

	if err != nil {
		return q, err
	}

	rc.policyCache.Add(script, q)
	return q, nil
}
