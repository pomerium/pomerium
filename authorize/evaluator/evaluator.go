// Package evaluator contains rego evaluators for evaluating authorize policy.
package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/go-set/v3"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/errgrouputil"
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
	cfg := getConfig(options...)

	err := updateStore(ctx, store, cfg)
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
	var cachedPolicyEvaluators map[uint64]*PolicyEvaluator
	if previous != nil && previous.cfgCacheKey == e.cfgCacheKey {
		e.headersEvaluators = previous.headersEvaluators
		cachedPolicyEvaluators = previous.policyEvaluators
	} else {
		e.headersEvaluators = NewHeadersEvaluator(store)
	}
	e.policyEvaluators, err = getOrCreatePolicyEvaluators(ctx, cfg, store, cachedPolicyEvaluators)
	if err != nil {
		return nil, err
	}

	return e, nil
}

type routeEvaluator struct {
	id        uint64
	evaluator *PolicyEvaluator
}

func getOrCreatePolicyEvaluators(
	ctx context.Context, cfg *evaluatorConfig, store *store.Store,
	cachedPolicyEvaluators map[uint64]*PolicyEvaluator,
) (map[uint64]*PolicyEvaluator, error) {
	now := time.Now()

	var reusedCount int
	m := make(map[uint64]*PolicyEvaluator)
	var builders []errgrouputil.BuilderFunc[routeEvaluator]
	for i := range cfg.Policies {
		configPolicy := cfg.Policies[i]
		id, err := configPolicy.RouteID()
		if err != nil {
			return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
		}
		p := cachedPolicyEvaluators[id]
		if p != nil && p.policyChecksum == configPolicy.Checksum() {
			m[id] = p
			reusedCount++
			continue
		}
		builders = append(builders, func(ctx context.Context) (*routeEvaluator, error) {
			evaluator, err := NewPolicyEvaluator(ctx, store, configPolicy, cfg.AddDefaultClientCertificateRule)
			if err != nil {
				return nil, fmt.Errorf("authorize: error building evaluator for route id=%s: %w", configPolicy.ID, err)
			}
			return &routeEvaluator{
				id:        id,
				evaluator: evaluator,
			}, nil
		})
	}

	evals, errs := errgrouputil.Build(ctx, builders...)
	if len(errs) > 0 {
		for _, err := range errs {
			log.Ctx(ctx).Error().Msg(err.Error())
		}
		return nil, fmt.Errorf("authorize: error building policy evaluators")
	}

	for _, p := range evals {
		m[p.id] = p.evaluator
	}

	log.Ctx(ctx).Debug().
		Dur("duration", time.Since(now)).
		Int("reused-policies", reusedCount).
		Int("created-policies", len(cfg.Policies)-reusedCount).
		Msg("updated policy evaluators")
	return m, nil
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
	"/.pomerium/routes",
	"/.pomerium/api/v1/routes",
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
	res, err := e.headersEvaluators.Evaluate(ctx, req)
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

func updateStore(ctx context.Context, store *store.Store, cfg *evaluatorConfig) error {
	jwk, err := getJWK(ctx, cfg)
	if err != nil {
		return fmt.Errorf("authorize: couldn't create signer: %w", err)
	}

	store.UpdateGoogleCloudServerlessAuthenticationServiceAccount(
		cfg.GoogleCloudServerlessAuthenticationServiceAccount,
	)
	store.UpdateJWTClaimHeaders(cfg.JWTClaimsHeaders)
	store.UpdateJWTGroupsFilter(cfg.JWTGroupsFilter)
	store.UpdateRoutePolicies(cfg.Policies)
	store.UpdateSigningKey(jwk)

	return nil
}

func getJWK(ctx context.Context, cfg *evaluatorConfig) (*jose.JSONWebKey, error) {
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
