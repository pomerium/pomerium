// Package evaluator contains rego evaluators for evaluating authorize policy.
package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

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

// notFoundOutput is what's returned if a route isn't found for a policy.
var notFoundOutput = &Result{
	Deny:    NewRuleResult(true, criteria.ReasonRouteNotFound),
	Headers: make(http.Header),
}

// Request contains the inputs needed for evaluation.
type Request struct {
	Policy  *config.Policy
	HTTP    RequestHTTP
	Session RequestSession
}

// RequestHTTP is the HTTP field in the request.
type RequestHTTP struct {
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	ClientCertificate string            `json:"client_certificate"`
	IP                string            `json:"ip"`
}

// NewRequestHTTP creates a new RequestHTTP.
func NewRequestHTTP(
	method string,
	requestURL url.URL,
	headers map[string]string,
	rawClientCertificate string,
	ip string,
) RequestHTTP {
	return RequestHTTP{
		Method:            method,
		Path:              requestURL.Path,
		URL:               requestURL.String(),
		Headers:           headers,
		ClientCertificate: rawClientCertificate,
		IP:                ip,
	}
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
	store             *store.Store
	policyEvaluators  map[uint64]*PolicyEvaluator
	headersEvaluators *HeadersEvaluator
	clientCA          []byte
}

// New creates a new Evaluator.
func New(ctx context.Context, store *store.Store, options ...Option) (*Evaluator, error) {
	e := &Evaluator{store: store}

	cfg := getConfig(options...)

	err := e.updateStore(cfg)
	if err != nil {
		return nil, err
	}

	e.headersEvaluators, err = NewHeadersEvaluator(ctx, store)
	if err != nil {
		return nil, err
	}

	e.policyEvaluators = make(map[uint64]*PolicyEvaluator)
	for _, configPolicy := range cfg.policies {
		id, err := configPolicy.RouteID()
		if err != nil {
			return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
		}
		policyEvaluator, err := NewPolicyEvaluator(ctx, store, &configPolicy) //nolint
		if err != nil {
			return nil, err
		}
		e.policyEvaluators[id] = policyEvaluator
	}

	e.clientCA = cfg.clientCA

	return e, nil
}

// Evaluate evaluates the rego for the given policy and generates the identity headers.
func (e *Evaluator) Evaluate(ctx context.Context, req *Request) (*Result, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.Evaluator.Evaluate")
	defer span.End()

	if req.Policy == nil {
		return notFoundOutput, nil
	}

	id, err := req.Policy.RouteID()
	if err != nil {
		return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
	}

	policyEvaluator, ok := e.policyEvaluators[id]
	if !ok {
		return notFoundOutput, nil
	}

	clientCA, err := e.getClientCA(req.Policy)
	if err != nil {
		return nil, err
	}

	isValidClientCertificate, err := isValidClientCertificate(clientCA, req.HTTP.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("authorize: error validating client certificate: %w", err)
	}

	eg, ectx := errgroup.WithContext(ctx)

	var policyOutput *PolicyResponse
	eg.Go(func() error {
		var err error
		policyOutput, err = policyEvaluator.Evaluate(ectx, &PolicyRequest{
			HTTP:                     req.HTTP,
			Session:                  req.Session,
			IsValidClientCertificate: isValidClientCertificate,
		})
		return err
	})

	var headersOutput *HeadersResponse
	eg.Go(func() error {
		headersReq := NewHeadersRequestFromPolicy(req.Policy)
		headersReq.Session = req.Session
		var err error
		headersOutput, err = e.headersEvaluators.Evaluate(ectx, headersReq)
		return err
	})

	err = eg.Wait()
	if err != nil {
		return nil, err
	}

	carryOverJWTAssertion(headersOutput.Headers, req.HTTP.Headers)

	res := &Result{
		Allow:   policyOutput.Allow,
		Deny:    policyOutput.Deny,
		Headers: headersOutput.Headers,
		Traces:  policyOutput.Traces,
	}
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

func (e *Evaluator) updateStore(cfg *evaluatorConfig) error {
	jwk, err := getJWK(cfg)
	if err != nil {
		return fmt.Errorf("authorize: couldn't create signer: %w", err)
	}

	e.store.UpdateGoogleCloudServerlessAuthenticationServiceAccount(
		cfg.googleCloudServerlessAuthenticationServiceAccount,
	)
	e.store.UpdateJWTClaimHeaders(cfg.jwtClaimsHeaders)
	e.store.UpdateRoutePolicies(cfg.policies)
	e.store.UpdateSigningKey(jwk)

	return nil
}

func getJWK(cfg *evaluatorConfig) (*jose.JSONWebKey, error) {
	var decodedCert []byte
	// if we don't have a signing key, generate one
	if len(cfg.signingKey) == 0 {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, fmt.Errorf("couldn't generate signing key: %w", err)
		}
		decodedCert, err = cryptutil.EncodePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("bad signing key: %w", err)
		}
	} else {
		decodedCert = cfg.signingKey
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
	jwtForKey := http.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertionFor)
	jwtFor, ok := src[jwtForKey]
	if ok && jwtFor != "" {
		dst.Add(jwtForKey, jwtFor)
		return
	}
	jwtFor, ok = src[http.CanonicalHeaderKey(httputil.HeaderPomeriumJWTAssertion)]
	if ok && jwtFor != "" {
		dst.Add(jwtForKey, jwtFor)
	}
}
