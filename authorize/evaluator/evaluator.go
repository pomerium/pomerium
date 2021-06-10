// Package evaluator contains rego evaluators for evaluating authorize policy.
package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// notFoundOutput is what's returned if a route isn't found for a policy.
var notFoundOutput = &Result{
	Allow: false,
	Deny: &Denial{
		Status:  http.StatusNotFound,
		Message: "route not found",
	},
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
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	ClientCertificate string            `json:"client_certificate"`
}

// RequestSession is the session field in the request.
type RequestSession struct {
	ID string `json:"id"`
}

// Result is the result of evaluation.
type Result struct {
	Allow   bool
	Deny    *Denial
	Headers http.Header

	DataBrokerServerVersion, DataBrokerRecordVersion uint64
}

// An Evaluator evaluates policies.
type Evaluator struct {
	store             *Store
	policyEvaluators  map[uint64]*PolicyEvaluator
	headersEvaluators *HeadersEvaluator
	clientCA          []byte
}

// New creates a new Evaluator.
func New(ctx context.Context, store *Store, options ...Option) (*Evaluator, error) {
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

	policyOutput, err := policyEvaluator.Evaluate(ctx, &PolicyRequest{
		HTTP:                     req.HTTP,
		Session:                  req.Session,
		IsValidClientCertificate: isValidClientCertificate,
	})
	if err != nil {
		return nil, err
	}

	headersReq := NewHeadersRequestFromPolicy(req.Policy)
	headersReq.Session = req.Session
	headersOutput, err := e.headersEvaluators.Evaluate(ctx, headersReq)
	if err != nil {
		return nil, err
	}

	carryOverJWTAssertion(headersOutput.Headers, req.HTTP.Headers)

	res := &Result{
		Allow:   policyOutput.Allow,
		Deny:    policyOutput.Deny,
		Headers: headersOutput.Headers,
	}
	res.DataBrokerServerVersion, res.DataBrokerRecordVersion = e.store.GetDataBrokerVersions()
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

	authenticateURL, err := urlutil.ParseAndValidateURL(cfg.authenticateURL)
	if err != nil {
		return fmt.Errorf("authorize: invalid authenticate URL: %w", err)
	}

	e.store.UpdateIssuer(authenticateURL.Host)
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
	if cfg.signingKey == "" {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, fmt.Errorf("couldn't generate signing key: %w", err)
		}
		decodedCert, err = cryptutil.EncodePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("bad signing key: %w", err)
		}
	} else {
		var err error
		decodedCert, err = base64.StdEncoding.DecodeString(cfg.signingKey)
		if err != nil {
			return nil, fmt.Errorf("bad signing key: %w", err)
		}
	}
	signingKeyAlgorithm := cfg.signingKeyAlgorithm
	if signingKeyAlgorithm == "" {
		signingKeyAlgorithm = string(jose.ES256)
	}

	jwk, err := cryptutil.PrivateJWKFromBytes(decodedCert, jose.SignatureAlgorithm(signingKeyAlgorithm))
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
