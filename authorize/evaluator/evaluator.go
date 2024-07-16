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

	"github.com/go-jose/go-jose/v3"
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

type EvaluatorCache struct {
	evalsMu             sync.RWMutex
	evaluatorsByRouteID map[uint64]*PolicyEvaluator
}

type QueryCache struct {
	queriesMu               sync.RWMutex
	queriesByScriptChecksum map[string]rego.PreparedEvalQuery
	sf                      singleflight.Group
}

func NewPolicyEvaluatorCache(initialSize int) *EvaluatorCache {
	return &EvaluatorCache{
		evaluatorsByRouteID: make(map[uint64]*PolicyEvaluator, initialSize),
	}
}

func NewQueryCache(initialSize int) *QueryCache {
	return &QueryCache{
		queriesByScriptChecksum: make(map[string]rego.PreparedEvalQuery, initialSize),
	}
}

func (c *EvaluatorCache) NumCachedEvaluators() int {
	c.evalsMu.RLock()
	defer c.evalsMu.RUnlock()
	return len(c.evaluatorsByRouteID)
}

func (c *EvaluatorCache) StoreEvaluator(routeID uint64, eval *PolicyEvaluator) {
	c.evalsMu.Lock()
	defer c.evalsMu.Unlock()
	c.evaluatorsByRouteID[routeID] = eval
}

func (c *EvaluatorCache) LookupEvaluator(routeID uint64) (*PolicyEvaluator, bool) {
	c.evalsMu.RLock()
	defer c.evalsMu.RUnlock()
	eval, ok := c.evaluatorsByRouteID[routeID]
	return eval, ok
}

func (c *QueryCache) NumCachedQueries() int {
	c.queriesMu.RLock()
	defer c.queriesMu.RUnlock()
	return len(c.queriesByScriptChecksum)
}

func (c *QueryCache) LookupOrBuild(q *policyQuery, builder func() (rego.PreparedEvalQuery, error)) (rego.PreparedEvalQuery, bool, error) {
	checksum := q.checksum()
	c.queriesMu.RLock()
	cached, ok := c.queriesByScriptChecksum[checksum]
	c.queriesMu.RUnlock()
	if ok {
		return cached, true, nil
	}
	pq, err, _ := c.sf.Do(checksum, func() (any, error) {
		res, err := builder()
		if err == nil {
			c.queriesMu.Lock()
			c.queriesByScriptChecksum[checksum] = res
			c.queriesMu.Unlock()
		}
		return res, err
	})
	if err != nil {
		return rego.PreparedEvalQuery{}, false, err
	}
	return pq.(rego.PreparedEvalQuery), false, nil
}

// An Evaluator evaluates policies.
type Evaluator struct {
	opts             *evaluatorOptions
	store            *store.Store
	evalCache        *EvaluatorCache
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

	var opts evaluatorOptions
	opts.apply(options...)

	e := &Evaluator{
		opts:  &opts,
		store: store,
	}

	if previous == nil || opts.cacheKey() != previous.opts.cacheKey() {
		var err error
		rttrace.WithRegion(ctx, "update store", func() {
			err = updateStore(store, &opts, previous)
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

type routeEvaluator struct {
	id               uint64
	evaluator        *PolicyEvaluator
	computedChecksum uint64
}

var (
	workerPoolSize      = runtime.NumCPU() - 1
	workerPoolTaskQueue = make(chan func(), workerPoolSize)
)

func init() {
	for i := 0; i < workerPoolSize; i++ {
		go worker()
	}
}

func worker() {
	for fn := range workerPoolTaskQueue {
		fn()
	}
}

const chunkSize = 64

type workerContext struct {
	context.Context
	cfg           *evaluatorOptions
	store         *store.Store
	statusBits    []uint64
	statusCounts  []uint8
	totalModified *atomic.Int32
	evaluators    []routeEvaluator
	evalCache     *EvaluatorCache
	queryCache    *QueryCache
	errs          *sync.Map
}

func computeChecksums(wctx *workerContext, chunkStart, chunkEnd int) {
	defer rttrace.StartRegion(wctx, "worker-checksum").End()
	for c := chunkStart; c < chunkEnd; c++ {
		var chunkStatus uint64
		off := c * chunkSize
		limit := min(chunkSize, len(wctx.cfg.Policies)-int(off))
		for i := 0; i < limit; i++ {
			p := &wctx.cfg.Policies[off+i]
			id, err := p.RouteID()
			if err != nil {
				wctx.errs.Store(off+i, fmt.Errorf("authorize: error computing policy route id: %w", err))
				continue
			}
			eval := &wctx.evaluators[off+i]
			eval.id = id
			eval.computedChecksum = p.ChecksumWithID(id)
			cached, ok := wctx.evalCache.LookupEvaluator(id)
			if !ok {
				rttrace.Logf(wctx, "", "policy with ID %d not found in cache", id)
				chunkStatus |= 1 << i
			} else if cached.policyChecksum != eval.computedChecksum {
				rttrace.Logf(wctx, "", "policy with ID %d changed", id)
				chunkStatus |= 1 << i
			}
		}
		wctx.statusBits[c] = chunkStatus
		popcnt := bits.OnesCount64(chunkStatus)
		rttrace.Logf(wctx, "", "chunk %d: %d/%d changed", c, popcnt, limit)
		wctx.statusCounts[c] = uint8(popcnt)
		wctx.totalModified.Add(int32(popcnt))
	}
}

func buildEvaluators(wctx *workerContext, partitions []int, workerIdx int) {
	defer rttrace.StartRegion(wctx, "worker-build").End()
	partitionStart := partitions[workerIdx]
	partitionEnd := partitions[workerIdx+1]
	addDefaultCert := wctx.cfg.AddDefaultClientCertificateRule
	var err error
	for c := partitionStart; c < partitionEnd; c++ {
		stat := wctx.statusBits[c]
		rttrace.Logf(wctx, "", "worker %d: chunk %d: status: %b", workerIdx, c, stat)
		for stat != 0 {
			bit := bits.TrailingZeros64(stat)
			stat &^= 1 << bit
			idx := bit + (chunkSize * c)
			p := &wctx.cfg.Policies[idx]
			eval := &wctx.evaluators[idx]
			eval.evaluator, err = NewPolicyEvaluator(wctx, wctx.store, p, eval.computedChecksum, addDefaultCert, wctx.queryCache)
			if err != nil {
				wctx.errs.Store(idx, err)
			}
		}
	}
}

func getOrCreatePolicyEvaluators(
	ctx context.Context,
	cfg *evaluatorOptions,
	store *store.Store,
	evalCache *EvaluatorCache,
	queryCache *QueryCache,
) error {
	rttrace.Logf(ctx, "", "using %d cached policy evaluators", evalCache.NumCachedEvaluators())
	now := time.Now()

	numChunks := len(cfg.Policies) / chunkSize
	if len(cfg.Policies)%chunkSize != 0 {
		numChunks++
	}
	statusBits := make([]uint64, numChunks) // 0=no change, 1=changed
	statusCounts := make([]uint8, numChunks)
	var totalModified atomic.Int32
	evaluators := make([]routeEvaluator, len(cfg.Policies))
	if len(evaluators) == 0 {
		return nil // nothing to do
	}
	numWorkers := min(workerPoolSize, numChunks)
	minChunksPerWorker := numChunks / numWorkers
	overflow := numChunks % numWorkers // number of workers which get an additional chunk

	wctx := &workerContext{
		Context:       ctx,
		cfg:           cfg,
		store:         store,
		statusBits:    statusBits,
		statusCounts:  statusCounts,
		totalModified: &totalModified,
		evaluators:    evaluators,
		evalCache:     evalCache,
		queryCache:    queryCache,
		errs:          &sync.Map{}, // slice index->error
	}

	// compute route checksums
	rttrace.WithRegion(ctx, "computing checksums", func() {
		var wg sync.WaitGroup
		wg.Add(numWorkers)
		chunkIdx := 0
		for workerIdx := range numWorkers {
			chunkStart := chunkIdx
			chunkEnd := chunkStart + minChunksPerWorker
			if workerIdx < overflow {
				chunkEnd++
			}
			chunkIdx = chunkEnd
			workerPoolTaskQueue <- func() {
				defer wg.Done()
				computeChecksums(wctx, chunkStart, chunkEnd)
			}
		}
		wg.Wait()
	})

	hasErrs := false
	wctx.errs.Range(func(key, value any) bool {
		log.Error(ctx).Msg(value.(error).Error())
		hasErrs = true
		return true
	})
	if hasErrs {
		return fmt.Errorf("authorize: error computing one or more policy route IDs")
	}

	if totalModified.Load() == 0 {
		return nil
	}

	// partitions here represent start indexes, since it is more likely that new
	// evaluators will be appended to the existing list, instead of prepended,
	// so we can more easily skip to the end of the list
	partitions := make([]int, 0, numWorkers+1)
	rttrace.WithRegion(ctx, "partitioning", func() {
		targetJobsPerWorker := max(uint32(totalModified.Load()/int32(numWorkers)), 1)
		numChunks := len(statusCounts)
		var chunkIdx int
		for statusBits[chunkIdx] == 0 {
			chunkIdx++
		}
		for chunkIdx < numChunks {
			partitions = append(partitions, chunkIdx)
			var accum uint32
			for chunkIdx < numChunks && accum < targetJobsPerWorker {
				accum += uint32(statusBits[chunkIdx])
				chunkIdx++
			}
		}
		numWorkers = min(numWorkers, len(partitions))
		partitions = append(partitions, numChunks)
	})

	// spawn workers
	rttrace.WithRegion(ctx, "running workers", func() {
		var wg sync.WaitGroup
		wg.Add(numWorkers)
		for workerIdx := range numWorkers {
			workerPoolTaskQueue <- func() {
				defer wg.Done()
				buildEvaluators(wctx, partitions, workerIdx)
			}
		}
		wg.Wait()
	})

	hasErrs = false
	wctx.errs.Range(func(key, value any) bool {
		log.Error(ctx).Msg(value.(error).Error())
		hasErrs = true
		return true
	})
	if hasErrs {
		return fmt.Errorf("authorize: error building policy evaluators")
	}

	updatedCount := 0
	for _, p := range evaluators {
		if p.evaluator != nil {
			updatedCount++
			evalCache.StoreEvaluator(p.id, p.evaluator)
		}
	}

	log.Debug(ctx).
		Dur("duration", time.Since(now)).
		Int("reused-policies", len(cfg.Policies)-int(totalModified.Load())).
		Int("created-policies", len(cfg.Policies)-updatedCount).
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

func (e *Evaluator) evaluateInternal(_ context.Context, req *Request) (*PolicyResponse, error) {
	// these endpoints require a logged-in user
	if req.HTTP.Path == "/.pomerium/webauthn" || req.HTTP.Path == "/.pomerium/jwt" {
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
	headersReq := NewHeadersRequestFromPolicy(req.Policy, req.HTTP)
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

func updateStore(store *store.Store, cfg *evaluatorOptions, previous *Evaluator) error {
	if previous == nil || !bytes.Equal(cfg.SigningKey, previous.opts.SigningKey) {
		jwk, err := getJWK(cfg.SigningKey)
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

func getJWK(signingKey []byte) (*jose.JSONWebKey, error) {
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
	log.Info(context.TODO()).Str("Algorithm", jwk.Algorithm).
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
