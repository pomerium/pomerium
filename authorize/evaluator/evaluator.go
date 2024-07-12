// Package evaluator contains rego evaluators for evaluating authorize policy.
package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/bits"
	"net/http"
	"net/url"
	"runtime"
	rttrace "runtime/trace"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/sync/errgroup"

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

// An Evaluator evaluates policies.
type Evaluator struct {
	store                 *store.Store
	policyEvaluators      map[uint64]*PolicyEvaluator
	headersEvaluators     *HeadersEvaluator
	clientCA              []byte
	clientCRL             []byte
	clientCertConstraints ClientCertConstraints

	cfgCacheKey uint64
}

// New creates a new Evaluator.
func New(
	ctx context.Context, store *store.Store, previous *Evaluator, options ...Option,
) (*Evaluator, error) {
	ctx, task := rttrace.NewTask(ctx, "evaluator.New")
	defer task.End()
	defer rttrace.StartRegion(ctx, "evaluator.New").End()

	cfg := getConfig(options...)

	err := updateStore(store, cfg)
	if err != nil {
		return nil, err
	}

	e := &Evaluator{
		store:                 store,
		clientCA:              cfg.ClientCA,
		clientCRL:             cfg.ClientCRL,
		clientCertConstraints: cfg.ClientCertConstraints,
		cfgCacheKey:           cfg.cacheKey(),
	}

	// If there is a previous Evaluator constructed from the same settings, we
	// can reuse the HeadersEvaluator along with any PolicyEvaluators for
	// unchanged policies.
	if previous != nil && previous.cfgCacheKey == e.cfgCacheKey {
		e.headersEvaluators = previous.headersEvaluators
		e.policyEvaluators = previous.policyEvaluators
	} else {
		e.headersEvaluators, err = NewHeadersEvaluator(ctx, store)
		if err != nil {
			return nil, err
		}
		e.policyEvaluators = make(map[uint64]*PolicyEvaluator, len(cfg.Policies))
	}
	if err := getOrCreatePolicyEvaluators(ctx, cfg, store, e.policyEvaluators); err != nil {
		return nil, err
	}

	return e, nil
}

type routeEvaluator struct {
	id        uint64
	evaluator *PolicyEvaluator
}

func getOrCreatePolicyEvaluators(
	ctx context.Context,
	cfg *evaluatorConfig,
	store *store.Store,
	cachedPolicyEvaluators map[uint64]*PolicyEvaluator,
) error {
	ctx, task := rttrace.NewTask(ctx, "evaluator.getOrCreatePolicyEvaluators")
	defer task.End()
	defer rttrace.StartRegion(ctx, "evaluator.getOrCreatePolicyEvaluators").End()

	rttrace.Logf(ctx, "", "using %d cached policy evaluators", len(cachedPolicyEvaluators))
	now := time.Now()

	const chunkSize = 64
	statusBits := make([]uint64, uint32(len(cfg.Policies))/chunkSize+1) // 0=no change, 1=changed
	statusCounts := make([]uint8, len(statusBits))
	var totalModified int
	evaluators := make([]routeEvaluator, len(cfg.Policies))
	if len(evaluators) == 0 {
		return nil // nothing to do
	}
	numWorkers := min(runtime.NumCPU(), len(statusBits))
	chunksPerWorker := len(statusBits) / numWorkers

	errs := sync.Map{} // slice index->error

	region := rttrace.StartRegion(ctx, "computing checksums")
	// compute route checksums
	{
		var wg sync.WaitGroup
		wg.Add(numWorkers)
		for workerIdx := range numWorkers {
			chunkStart := workerIdx * chunksPerWorker
			chunkEnd := chunkStart + chunksPerWorker
			go func() {
				ctx, task := rttrace.NewTask(ctx, fmt.Sprintf("worker-%d", workerIdx))
				defer task.End()
				defer rttrace.StartRegion(ctx, "worker").End()
				defer wg.Done()
				for c := chunkStart; c < chunkEnd; c++ {
					var chunkStatus uint64
					off := c * chunkSize
					limit := min(chunkSize, len(cfg.Policies)-int(off))
					for i := 0; i < limit; i++ {
						p := &cfg.Policies[off+i]
						id, err := p.RouteID()
						if err != nil {
							errs.Store(off+i, fmt.Errorf("authorize: error computing policy route id: %w", err))
							continue
						}
						evaluators[off+i].id = id
						actual := p.Checksum()
						cached, ok := cachedPolicyEvaluators[id]
						if !ok {
							rttrace.Logf(ctx, "", "policy with ID %d not found in cache", id)
							chunkStatus |= 1 << i
						} else if cached.policyChecksum != actual {
							rttrace.Logf(ctx, "", "policy with ID %d changed", id)
							chunkStatus |= 1 << i
						}
					}
					statusBits[c] = chunkStatus
					popcnt := bits.OnesCount64(chunkStatus)
					rttrace.Logf(ctx, "", "chunk %d: %d/%d changed", c, popcnt, limit)
					statusCounts[c] = uint8(popcnt)
					totalModified += popcnt
				}
			}()
		}
		wg.Wait()
	}
	region.End()

	hasErrs := false
	errs.Range(func(key, value any) bool {
		errPolicy := evaluators[key.(int)]
		delete(cachedPolicyEvaluators, errPolicy.id)
		log.Error(ctx).Msg(value.(error).Error())
		hasErrs = true
		return true
	})
	if hasErrs {
		return fmt.Errorf("authorize: error computing one or more policy route IDs")
	}

	if totalModified == 0 {
		return nil
	}

	region = rttrace.StartRegion(ctx, "partitioning")
	partitions := make([]int, numWorkers)
	{
		targetJobsPerWorker := uint32(totalModified / numWorkers)
		chunk := 0
		numChunks := len(statusCounts)
		for worker := 0; worker < numWorkers && chunk < numChunks; worker++ {
			// find the end partition for each worker
			accum := uint32(0)
			for accum < targetJobsPerWorker && chunk < numChunks {
				accum += uint32(statusCounts[chunk])
				chunk++
			}
			partitions[worker] = chunk
		}
		// add anything remaining to the last worker
		if chunk != numChunks {
			partitions[len(partitions)-1] = numChunks
		}
	}
	region.End()

	region = rttrace.StartRegion(ctx, "running workers")
	// spawn workers
	{
		var wg sync.WaitGroup
		for worker := range numWorkers {
			partitionStart := 0
			if worker > 0 {
				partitionStart = partitions[worker-1]
			}
			partitionEnd := partitions[worker]
			wg.Add(1)
			go func() {
				ctx, task := rttrace.NewTask(ctx, fmt.Sprintf("worker-%d", worker))
				defer task.End()
				defer rttrace.StartRegion(ctx, "worker").End()

				defer wg.Done()
				var err error
				for c := partitionStart; c < partitionEnd; c++ {
					stat := statusBits[c]
					rttrace.Logf(ctx, "", "worker %d: chunk %d: status: %b", worker, c, stat)
					for stat != 0 {
						bit := bits.TrailingZeros64(stat)
						stat &^= 1 << bit
						idx := bit + (chunkSize * c)
						p := &cfg.Policies[idx]
						evaluators[idx].evaluator, err = NewPolicyEvaluator(ctx, store, p, cfg.AddDefaultClientCertificateRule)
						if err != nil {
							errs.Store(idx, err)
						}
					}
				}
			}()
		}
		wg.Wait()
	}
	region.End()

	hasErrs = false
	errs.Range(func(key, value any) bool {
		errPolicy := evaluators[key.(int)]
		delete(cachedPolicyEvaluators, errPolicy.id)
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
			cachedPolicyEvaluators[p.id] = p.evaluator
		}
	}

	log.Debug(ctx).
		Dur("duration", time.Since(now)).
		Int("reused-policies", len(cfg.Policies)-totalModified).
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

	policyEvaluator, ok := e.policyEvaluators[id]
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
		clientCA, string(e.clientCRL), req.HTTP.ClientCertificate, e.clientCertConstraints)
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
	res, err := e.headersEvaluators.Evaluate(ctx, headersReq)
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

	return string(e.clientCA), nil
}

func updateStore(store *store.Store, cfg *evaluatorConfig) error {
	jwk, err := getJWK(cfg)
	if err != nil {
		return fmt.Errorf("authorize: couldn't create signer: %w", err)
	}

	store.UpdateGoogleCloudServerlessAuthenticationServiceAccount(
		cfg.GoogleCloudServerlessAuthenticationServiceAccount,
	)
	store.UpdateJWTClaimHeaders(cfg.JWTClaimsHeaders)
	store.UpdateRoutePolicies(cfg.Policies)
	store.UpdateSigningKey(jwk)

	return nil
}

func getJWK(cfg *evaluatorConfig) (*jose.JSONWebKey, error) {
	var decodedCert []byte
	// if we don't have a signing key, generate one
	if len(cfg.SigningKey) == 0 {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, fmt.Errorf("couldn't generate signing key: %w", err)
		}
		decodedCert, err = cryptutil.EncodePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("bad signing key: %w", err)
		}
	} else {
		decodedCert = cfg.SigningKey
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
