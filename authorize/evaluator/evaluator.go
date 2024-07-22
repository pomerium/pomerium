// Package evaluator contains rego evaluators for evaluating authorize policy.
package evaluator

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"math/bits"
	"net/http"
	"net/url"
	"runtime"
	rttrace "runtime/trace"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/go-set/v3"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// Request contains the inputs needed for evaluation.
type Request struct {
	IsInternal bool
	Policy     *config.Policy
	HTTP       RequestHTTP
	Session    RequestSession
}

// RequestHTTP is the HTTP field in the request.
type RequestHTTP struct {
	Method            string                `json:"method"`
	Hostname          string                `json:"hostname"`
	Path              string                `json:"path"`
	URL               string                `json:"url"`
	Headers           map[string]string     `json:"headers"`
	ClientCertificate ClientCertificateInfo `json:"client_certificate"`
	IP                string                `json:"ip"`
}

// NewRequestHTTP creates a new RequestHTTP.
func NewRequestHTTP(
	method string,
	requestURL url.URL,
	headers map[string]string,
	clientCertificate ClientCertificateInfo,
	ip string,
) RequestHTTP {
	return RequestHTTP{
		Method:            method,
		Hostname:          requestURL.Hostname(),
		Path:              requestURL.Path,
		URL:               requestURL.String(),
		Headers:           headers,
		ClientCertificate: clientCertificate,
		IP:                ip,
	}
}

// ClientCertificateInfo contains information about the certificate presented
// by the client (if any).
type ClientCertificateInfo struct {
	// Presented is true if the client presented a certificate.
	Presented bool `json:"presented"`

	// Leaf contains the leaf client certificate (unvalidated).
	Leaf string `json:"leaf,omitempty"`

	// Intermediates contains the remainder of the client certificate chain as
	// it was originally presented by the client (unvalidated).
	Intermediates string `json:"intermediates,omitempty"`
}

// RequestSession is the session field in the request.
type RequestSession struct {
	ID string `json:"id"`
}

// Result is the result of evaluation.
type Result struct {
	Allow   RuleResult
	Deny    RuleResult
	Headers http.Header
	Traces  []contextutil.PolicyEvaluationTrace
}

type PolicyEvaluatorCacheStats struct {
	CacheHits   int64
	CacheMisses int64
}

type PolicyEvaluatorCache struct {
	evalsMu             sync.RWMutex
	evaluatorsByRouteID map[uint64]*PolicyEvaluator

	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

type QueryCacheStats struct {
	CacheHits       int64
	CacheMisses     int64
	BuildsSucceeded int64
	BuildsFailed    int64
	BuildsShared    int64
}

type QueryCache struct {
	queriesMu               sync.RWMutex
	queriesByScriptChecksum map[string]rego.PreparedEvalQuery
	sf                      singleflight.Group

	cacheHits       atomic.Int64
	cacheMisses     atomic.Int64
	buildsSucceeded atomic.Int64
	buildsFailed    atomic.Int64
	buildsShared    atomic.Int64
}

func NewPolicyEvaluatorCache(initialSize int) *PolicyEvaluatorCache {
	return &PolicyEvaluatorCache{
		evaluatorsByRouteID: make(map[uint64]*PolicyEvaluator, initialSize),
	}
}

func NewQueryCache(initialSize int) *QueryCache {
	return &QueryCache{
		queriesByScriptChecksum: make(map[string]rego.PreparedEvalQuery, initialSize),
	}
}

func (c *PolicyEvaluatorCache) NumCachedEvaluators() int {
	c.evalsMu.RLock()
	defer c.evalsMu.RUnlock()
	return len(c.evaluatorsByRouteID)
}

func (c *PolicyEvaluatorCache) StoreEvaluator(routeID uint64, eval *PolicyEvaluator) {
	c.evalsMu.Lock()
	defer c.evalsMu.Unlock()
	c.evaluatorsByRouteID[routeID] = eval
}

func (c *PolicyEvaluatorCache) LookupEvaluator(routeID uint64) (*PolicyEvaluator, bool) {
	c.evalsMu.RLock()
	defer c.evalsMu.RUnlock()
	eval, ok := c.evaluatorsByRouteID[routeID]
	if ok {
		c.cacheHits.Add(1)
	} else {
		c.cacheMisses.Add(1)
	}
	return eval, ok
}

func (c *PolicyEvaluatorCache) Stats() PolicyEvaluatorCacheStats {
	return PolicyEvaluatorCacheStats{
		CacheHits:   c.cacheHits.Load(),
		CacheMisses: c.cacheMisses.Load(),
	}
}

func (c *QueryCache) NumCachedQueries() int {
	c.queriesMu.RLock()
	defer c.queriesMu.RUnlock()
	return len(c.queriesByScriptChecksum)
}

func (c *QueryCache) Stats() QueryCacheStats {
	return QueryCacheStats{
		CacheHits:       c.cacheHits.Load(),
		CacheMisses:     c.cacheMisses.Load(),
		BuildsSucceeded: c.buildsSucceeded.Load(),
		BuildsFailed:    c.buildsFailed.Load(),
		BuildsShared:    c.buildsShared.Load(),
	}
}

func (c *QueryCache) LookupOrBuild(q *policyQuery, builder func() (rego.PreparedEvalQuery, error)) (rego.PreparedEvalQuery, bool, error) {
	checksum := q.checksum()
	c.queriesMu.RLock()
	cached, ok := c.queriesByScriptChecksum[checksum]
	c.queriesMu.RUnlock()
	if ok {
		c.cacheHits.Add(1)
		return cached, true, nil
	}
	c.cacheMisses.Add(1)
	var ours bool
	pq, err, shared := c.sf.Do(checksum, func() (any, error) {
		ours = true
		res, err := builder()
		if err == nil {
			c.queriesMu.Lock()
			c.queriesByScriptChecksum[checksum] = res
			c.queriesMu.Unlock()
			c.buildsSucceeded.Add(1)
		} else {
			c.buildsFailed.Add(1)
		}
		return res, err
	})
	if err != nil {
		return rego.PreparedEvalQuery{}, false, err
	}
	if shared && !ours {
		c.buildsShared.Add(1)
	}
	return pq.(rego.PreparedEvalQuery), false, nil
}

// An Evaluator evaluates policies.
type Evaluator struct {
	opts             *evaluatorConfig
	store            *store.Store
	evalCache        *PolicyEvaluatorCache
	queryCache       *QueryCache
	headersEvaluator *HeadersEvaluator
}

// New creates a new Evaluator.
func New(
	ctx context.Context,
	store *store.Store,
	previous *Evaluator,
	options ...Option,
) (*Evaluator, error) {
	ctx, task := rttrace.NewTask(ctx, "evaluator.New")
	defer task.End()
	defer rttrace.StartRegion(ctx, "evaluator.New").End()

	var opts evaluatorConfig
	opts.apply(options...)

	e := &Evaluator{
		opts:  &opts,
		store: store,
	}

	if previous == nil || opts.cacheKey() != previous.opts.cacheKey() || store != previous.store {
		var err error
		rttrace.WithRegion(ctx, "update store", func() {
			err = updateStore(ctx, store, &opts, previous)
		})
		if err != nil {
			return nil, err
		}

		rttrace.WithRegion(ctx, "create headers evaluator", func() {
			e.headersEvaluator, err = NewHeadersEvaluator(ctx, store)
		})
		if err != nil {
			return nil, err
		}

		e.evalCache = NewPolicyEvaluatorCache(len(opts.Policies))
		e.queryCache = NewQueryCache(len(opts.Policies))
	} else {
		// If there is a previous Evaluator constructed from the same settings, we
		// can reuse the HeadersEvaluator along with any PolicyEvaluators for
		// unchanged policies.
		e.headersEvaluator = previous.headersEvaluator
		e.evalCache = previous.evalCache
		e.queryCache = previous.queryCache
	}

	var err error
	rttrace.WithRegion(ctx, "update policy evaluators", func() {
		err = getOrCreatePolicyEvaluators(ctx, &opts, store, e.evalCache, e.queryCache)
	})
	if err != nil {
		return nil, err
	}

	return e, nil
}

var (
	workerPoolSize      = runtime.NumCPU() - 1
	workerPoolMu        sync.Mutex
	workerPoolTaskQueue = make(chan func(), (workerPoolSize+1)*2)
)

func init() {
	for i := 0; i < workerPoolSize; i++ {
		// the worker function is separate so that it shows up in stack traces as
		// 'worker' instead of an anonymous function in init()
		go worker()
	}
}

func worker() {
	workerPoolMu.Lock()
	queue := workerPoolTaskQueue
	workerPoolMu.Unlock()
	for fn := range queue {
		fn()
	}
}

type chunkSizes interface {
	uint8 | uint16 | uint32 | uint64
}

// returns the size in bits for any allowed type in chunkSizes
func chunkSize[T chunkSizes]() int {
	return int(unsafe.Sizeof(T(0))) * 8
}

type workerContext[T chunkSizes] struct {
	context.Context
	Cfg        *evaluatorConfig
	Store      *store.Store
	StatusBits []T
	Evaluators []routeEvaluator
	EvalCache  *PolicyEvaluatorCache
	QueryCache *QueryCache
	Errs       *sync.Map
}

type routeEvaluator struct {
	ID               uint64           // route id
	Evaluator        *PolicyEvaluator // the compiled evaluator
	ComputedChecksum uint64           // cached evaluator checksum
}

// partition represents a range of chunks (fixed-size blocks of policies)
// corresponding to the Cfg.Policies, StatusBits, and Evaluators fields in
// the workerContext. It is the slice [Begin*chunkSize:End*chunkSize] w.r.t.
// those fields, but each index represents a unit of work that can be done in
// parallel with work on other chunks.
type partition struct{ Begin, End int }

// computeChecksums is a worker task that computes policy checksums and updates
// StatusBits to flag policies that need to be rebuilt. It operates on entire
// chunks (fixed-size blocks of policies), given by the start and end indexes
// in the partition argument, and updates the corresponding indexes of the
// StatusBits field of the worker context for those chunks.
func computeChecksums[T chunkSizes](wctx *workerContext[T], part partition) {
	defer rttrace.StartRegion(wctx, "worker-checksum").End()
	for chunkIdx := part.Begin; chunkIdx < part.End; chunkIdx++ {
		var chunkStatus T
		chunkSize := chunkSize[T]()
		off := chunkIdx * chunkSize // chunk offset
		// If there are fewer than chunkSize policies remaining in the actual list,
		// don't go beyond the end
		limit := min(chunkSize, len(wctx.Cfg.Policies)-off)
		popcount := 0
		for i := range limit {
			p := wctx.Cfg.Policies[off+i]
			// Compute the route id; this value is reused later as the route name
			// when computing the checksum
			id, err := p.RouteID()
			if err != nil {
				wctx.Errs.Store(off+i, fmt.Errorf("authorize: error computing policy route id: %w", err))
				continue
			}
			eval := &wctx.Evaluators[off+i]
			eval.ID = id
			// Compute the policy checksum and cache it in the evaluator, reusing
			// the route ID from before (to avoid needing to compute it again)
			eval.ComputedChecksum = p.Checksum()
			// eval.ComputedChecksum = p.ChecksumWithID(id) // TODO: update this when merged

			// Check if there is an existing evaluator cached for the route ID
			// NB: the route ID is composed of a subset of fields of the Policy; this
			// means the cache will hit if the route ID fields are the same, even if
			// other fields in the policy differ.
			cached, ok := wctx.EvalCache.LookupEvaluator(id)
			if !ok {
				rttrace.Logf(wctx, "", "policy for route ID %d not found in cache", id)
				chunkStatus |= T(1 << i)
				popcount++
			} else if cached.policyChecksum != eval.ComputedChecksum {
				// Route ID is the same, but the full checksum differs
				rttrace.Logf(wctx, "", "policy for route ID %d changed", id)
				chunkStatus |= T(1 << i)
				popcount++
			}
			// On a cache hit, chunkStatus for the ith bit stays at 0
		}
		// Set chunkStatus bitmask all at once (for better locality)
		wctx.StatusBits[chunkIdx] = chunkStatus
		rttrace.Logf(wctx, "", "chunk %d: %d/%d changed", chunkIdx, popcount, limit)
	}
}

// buildEvaluators is a worker task that creates new policy evaluators. It
// operates on entire chunks (fixed-size blocks of policies), given by the start
// and end indexes in the partition argument, and updates the corresponding
// indexes of the Evaluators field of the worker context for those chunks.
func buildEvaluators[T chunkSizes](wctx *workerContext[T], part partition) {
	chunkSize := chunkSize[T]()
	defer rttrace.StartRegion(wctx, "worker-build").End()
	addDefaultCert := wctx.Cfg.AddDefaultClientCertificateRule
	var err error
	for chunkIdx := part.Begin; chunkIdx < part.End; chunkIdx++ {
		// Obtain the bitmask computed by computeChecksums for this chunk
		stat := wctx.StatusBits[chunkIdx]
		rttrace.Logf(wctx, "", "chunk %d: status: %0*b", chunkIdx, chunkSize, stat)

		// Iterate over all the set bits in stat. This works by finding the
		// lowest set bit, zeroing it, and repeating. The go compiler will
		// replace [bits.TrailingZeros64] with intrinsics on most platforms.
		for stat != 0 {
			bit := bits.TrailingZeros64(uint64(stat)) // find the lowest set bit
			stat &= (stat - 1)                        // clear the lowest set bit
			idx := (chunkSize * chunkIdx) + bit
			p := wctx.Cfg.Policies[idx]
			eval := &wctx.Evaluators[idx]
			eval.Evaluator, err = NewPolicyEvaluator(wctx, wctx.Store, p, eval.ComputedChecksum, addDefaultCert, wctx.QueryCache)
			if err != nil {
				wctx.Errs.Store(idx, err)
			}
		}
	}
}

// bestChunkSize determines the chunk size (8, 16, 32, or 64) to use for the
// given number of policies and workers.
func bestChunkSize(numPolicies, numWorkers int) int {
	// use the chunk size that results in the largest number of chunks without
	// going past the number of workers. this results in the following behavior:
	// - as the number of policies increases, chunk size tends to increase
	// - as the number of workers increases, chunk size tends to decrease
	sizes := []int{64, 32, 16, 8}
	sizeIdx := 0
	for i, size := range sizes {
		if float64(numPolicies)/float64(size) > float64(numWorkers) {
			break
		}
		sizeIdx = i
	}
	return sizes[sizeIdx]
}

func getOrCreatePolicyEvaluators(
	ctx context.Context,
	cfg *evaluatorConfig,
	store *store.Store,
	evalCache *PolicyEvaluatorCache,
	queryCache *QueryCache,
) error {
	chunkSize := bestChunkSize(len(cfg.Policies), workerPoolSize)
	switch chunkSize {
	case 8:
		return getOrCreatePolicyEvaluatorsT[uint8](ctx, cfg, store, evalCache, queryCache)
	case 16:
		return getOrCreatePolicyEvaluatorsT[uint16](ctx, cfg, store, evalCache, queryCache)
	case 32:
		return getOrCreatePolicyEvaluatorsT[uint32](ctx, cfg, store, evalCache, queryCache)
	case 64:
		return getOrCreatePolicyEvaluatorsT[uint64](ctx, cfg, store, evalCache, queryCache)
	}
	panic("unreachable")
}

func getOrCreatePolicyEvaluatorsT[T chunkSizes](
	ctx context.Context,
	cfg *evaluatorConfig,
	store *store.Store,
	evalCache *PolicyEvaluatorCache,
	queryCache *QueryCache,
) error {
	chunkSize := bestChunkSize(len(cfg.Policies), workerPoolSize)
	rttrace.Logf(ctx, "", "eval cache size: %d; query cache size: %d; chunk size: %d",
		evalCache.NumCachedEvaluators(), queryCache.NumCachedQueries(), chunkSize)
	now := time.Now()

	// Split the policy list into chunks which can individually be operated on in
	// parallel with other chunks. Each chunk has a corresponding bitmask in the
	// statusBits list which is used to indicate to workers which policy
	// evaluators (at indexes in the chunk corresponding to set bits) need to be
	// built, or rebuilt due to changes.
	numChunks := len(cfg.Policies) / chunkSize
	if len(cfg.Policies)%chunkSize != 0 {
		numChunks++
	}
	statusBits := make([]T, numChunks) // bits map directly to policy indexes
	evaluators := make([]routeEvaluator, len(cfg.Policies))
	if len(evaluators) == 0 {
		return nil // nothing to do
	}
	// Limit the number of workers to the size of the worker pool; since we are
	// manually distributing chunks between workers, we can avoid spawning more
	// goroutines than we need, and instead giving each worker additional chunks.
	numWorkers := min(workerPoolSize, numChunks)
	// Each worker is given a minimum number of chunks, then the remainder are
	// spread evenly between workers.
	minChunksPerWorker := numChunks / numWorkers
	overflow := numChunks % numWorkers // number of workers which get an additional chunk

	wctx := &workerContext[T]{
		Context:    ctx,
		Cfg:        cfg,
		Store:      store,
		StatusBits: statusBits,
		Evaluators: evaluators,
		EvalCache:  evalCache,
		QueryCache: queryCache,
		Errs:       &sync.Map{}, // policy index->error
	}

	// First, build a list of partitions (start/end chunk indexes) to send to
	// each worker.
	partitions := make([]partition, numWorkers)
	rttrace.WithRegion(ctx, "partitioning", func() {
		chunkIdx := 0
		for workerIdx := range numWorkers {
			chunkStart := chunkIdx
			chunkEnd := chunkStart + minChunksPerWorker
			if workerIdx < overflow {
				chunkEnd++
			}
			chunkIdx = chunkEnd
			partitions[workerIdx] = partition{chunkStart, chunkEnd}
		}
	})

	// Compute all route checksums in parallel to determine which routes need to
	// be rebuilt.
	rttrace.WithRegion(ctx, "computing checksums", func() {
		var wg sync.WaitGroup
		for _, part := range partitions {
			wg.Add(1)
			workerPoolTaskQueue <- func() {
				defer wg.Done()
				computeChecksums(wctx, part)
			}
		}
		wg.Wait()
	})

	hasErrs := false
	wctx.Errs.Range(func(key, value any) bool {
		log.Ctx(ctx).Error().Int("policy-index", key.(int)).Msg(value.(error).Error())
		hasErrs = true
		return true
	})
	if hasErrs {
		return fmt.Errorf("authorize: error computing one or more policy route IDs")
	}

	// After all checksums are computed and status bits populated, build the
	// required evaluators.
	rttrace.WithRegion(ctx, "building evaluators", func() {
		var wg sync.WaitGroup
		for _, part := range partitions {
			// Adjust the partition to skip over chunks with 0 bits set
			for part.Begin < part.End && statusBits[part.Begin] == 0 {
				part.Begin++
			}
			for part.Begin < (part.End)-1 && statusBits[part.End-1] == 0 {
				part.End--
			}
			if part.Begin == part.End {
				continue
			}
			wg.Add(1)
			workerPoolTaskQueue <- func() {
				defer wg.Done()
				buildEvaluators(wctx, part)
			}
		}
		wg.Wait()
	})

	hasErrs = false
	wctx.Errs.Range(func(key, value any) bool {
		log.Ctx(ctx).Error().Int("policy-index", key.(int)).Msg(value.(error).Error())
		hasErrs = true
		return true
	})
	if hasErrs {
		return fmt.Errorf("authorize: error building policy evaluators")
	}

	// Store updated evaluators in the cache
	updatedCount := 0
	for _, p := range evaluators {
		if p.Evaluator != nil { // these are only set when modified
			updatedCount++
			evalCache.StoreEvaluator(p.ID, p.Evaluator)
		}
	}

	log.Ctx(ctx).Debug().
		Dur("duration", time.Since(now)).
		Int("reused-policies", len(cfg.Policies)-updatedCount).
		Int("created-policies", updatedCount).
		Msg("updated policy evaluators")
	return nil
}

// Evaluate evaluates the rego for the given policy and generates the identity headers.
func (e *Evaluator) Evaluate(ctx context.Context, req *Request) (*Result, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.Evaluator.Evaluate")
	defer span.End()

	eg, ctx := errgroup.WithContext(ctx)

	var policyOutput *PolicyResponse
	eg.Go(func() error {
		var err error
		if req.IsInternal {
			policyOutput, err = e.evaluateInternal(ctx, req)
		} else {
			policyOutput, err = e.evaluatePolicy(ctx, req)
		}
		return err
	})

	var headersOutput *HeadersResponse
	eg.Go(func() error {
		var err error
		headersOutput, err = e.evaluateHeaders(ctx, req)
		return err
	})

	err := eg.Wait()
	if err != nil {
		return nil, err
	}

	res := &Result{
		Allow:   policyOutput.Allow,
		Deny:    policyOutput.Deny,
		Headers: headersOutput.Headers,
		Traces:  policyOutput.Traces,
	}
	return res, nil
}

// Internal endpoints that require a logged-in user.
var internalPathsNeedingLogin = set.From([]string{
	"/.pomerium/jwt",
	"/.pomerium/user",
	"/.pomerium/webauthn",
})

func (e *Evaluator) evaluateInternal(_ context.Context, req *Request) (*PolicyResponse, error) {
	if internalPathsNeedingLogin.Contains(req.HTTP.Path) {
		if req.Session.ID == "" {
			return &PolicyResponse{
				Allow: NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			}, nil
		}
	}

	return &PolicyResponse{
		Allow: NewRuleResult(true, criteria.ReasonPomeriumRoute),
	}, nil
}

func (e *Evaluator) evaluatePolicy(ctx context.Context, req *Request) (*PolicyResponse, error) {
	if req.Policy == nil {
		return &PolicyResponse{
			Deny: NewRuleResult(true, criteria.ReasonRouteNotFound),
		}, nil
	}

	id, err := req.Policy.RouteID()
	if err != nil {
		return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
	}

	policyEvaluator, ok := e.evalCache.LookupEvaluator(id)
	if !ok {
		return &PolicyResponse{
			Deny: NewRuleResult(true, criteria.ReasonRouteNotFound),
		}, nil
	}

	clientCA, err := e.getClientCA(req.Policy)
	if err != nil {
		return nil, err
	}

	isValidClientCertificate, err := isValidClientCertificate(
		clientCA, string(e.opts.ClientCRL), req.HTTP.ClientCertificate, e.opts.ClientCertConstraints)
	if err != nil {
		return nil, fmt.Errorf("authorize: error validating client certificate: %w", err)
	}

	return policyEvaluator.Evaluate(ctx, &PolicyRequest{
		HTTP:                     req.HTTP,
		Session:                  req.Session,
		IsValidClientCertificate: isValidClientCertificate,
	})
}

func (e *Evaluator) evaluateHeaders(ctx context.Context, req *Request) (*HeadersResponse, error) {
	headersReq, err := NewHeadersRequestFromPolicy(req.Policy, req.HTTP)
	if err != nil {
		return nil, err
	}
	headersReq.Session = req.Session
	res, err := e.headersEvaluator.Evaluate(ctx, headersReq)
	if err != nil {
		return nil, err
	}

	carryOverJWTAssertion(res.Headers, req.HTTP.Headers)

	return res, nil
}

func (e *Evaluator) getClientCA(policy *config.Policy) (string, error) {
	if policy != nil && policy.TLSDownstreamClientCA != "" {
		bs, err := base64.StdEncoding.DecodeString(policy.TLSDownstreamClientCA)
		if err != nil {
			return "", err
		}
		return string(bs), nil
	}

	return string(e.opts.ClientCA), nil
}

func updateStore(ctx context.Context, store *store.Store, cfg *evaluatorConfig, previous *Evaluator) error {
	if previous == nil || !bytes.Equal(cfg.SigningKey, previous.opts.SigningKey) {
		jwk, err := getJWK(ctx, cfg.SigningKey)
		if err != nil {
			return fmt.Errorf("authorize: couldn't create signer: %w", err)
		}
		store.UpdateSigningKey(jwk)
	}

	if previous == nil || cfg.GoogleCloudServerlessAuthenticationServiceAccount != previous.opts.GoogleCloudServerlessAuthenticationServiceAccount {
		store.UpdateGoogleCloudServerlessAuthenticationServiceAccount(
			cfg.GoogleCloudServerlessAuthenticationServiceAccount,
		)
	}

	if previous == nil || !maps.Equal(cfg.JWTClaimsHeaders, previous.opts.JWTClaimsHeaders) {
		store.UpdateJWTClaimHeaders(cfg.JWTClaimsHeaders)
	}

	store.UpdateRoutePolicies(cfg.Policies)
	return nil
}

func getJWK(ctx context.Context, signingKey []byte) (*jose.JSONWebKey, error) {
	var decodedCert []byte
	// if we don't have a signing key, generate one
	if len(signingKey) == 0 {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, fmt.Errorf("couldn't generate signing key: %w", err)
		}
		decodedCert, err = cryptutil.EncodePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("bad signing key: %w", err)
		}
	} else {
		decodedCert = signingKey
	}

	jwk, err := cryptutil.PrivateJWKFromBytes(decodedCert)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate signing key: %w", err)
	}
	log.Ctx(ctx).Info().Str("Algorithm", jwk.Algorithm).
		Str("KeyID", jwk.KeyID).
		Interface("Public Key", jwk.Public()).
		Msg("authorize: signing key")

	return jwk, nil
}

func safeEval(ctx context.Context, q rego.PreparedEvalQuery, options ...rego.EvalOption) (resultSet rego.ResultSet, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	resultSet, err = q.Eval(ctx, options...)
	return resultSet, err
}

// carryOverJWTAssertion copies assertion JWT from request to response
// note that src keys are expected to be http.CanonicalHeaderKey
func carryOverJWTAssertion(dst http.Header, src map[string]string) {
	jwtForKey := httputil.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertionFor)
	jwtFor, ok := src[jwtForKey]
	if ok && jwtFor != "" {
		dst.Add(jwtForKey, jwtFor)
		return
	}
	jwtFor, ok = src[httputil.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertion)]
	if ok && jwtFor != "" {
		dst.Add(jwtForKey, jwtFor)
	}
}
