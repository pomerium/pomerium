// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator struct {
	custom   *CustomEvaluator
	rego     *rego.Rego
	query    rego.PreparedEvalQuery
	policies []config.Policy
	store    *Store
}

// New creates a new Evaluator.
func New(options *config.Options, store *Store) (*Evaluator, error) {
	e := &Evaluator{
		custom:   NewCustomEvaluator(store.opaStore),
		policies: options.GetAllPolicies(),
		store:    store,
	}
	jwk, err := getJWK(options)
	if err != nil {
		return nil, fmt.Errorf("authorize: couldn't create signer: %w", err)
	}

	authzPolicy, err := readPolicy("/authz.rego")
	if err != nil {
		return nil, fmt.Errorf("error loading rego policy: %w", err)
	}

	store.UpdateIssuer(options.AuthenticateURL.Host)
	store.UpdateGoogleCloudServerlessAuthenticationServiceAccount(options.GoogleCloudServerlessAuthenticationServiceAccount)
	store.UpdateJWTClaimHeaders(options.JWTClaimsHeaders)
	store.UpdateRoutePolicies(options.GetAllPolicies())
	store.UpdateSigningKey(jwk)

	e.rego = rego.New(
		rego.Store(store.opaStore),
		rego.Module("pomerium.authz", string(authzPolicy)),
		rego.Query("result = data.pomerium.authz"),
		getGoogleCloudServerlessHeadersRegoOption,
	)

	e.query, err = e.rego.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error preparing rego query: %w", err)
	}

	return e, nil
}

// Evaluate evaluates the policy against the request.
func (e *Evaluator) Evaluate(ctx context.Context, req *Request) (*Result, error) {
	isValid, err := isValidClientCertificate(req.ClientCA, req.HTTP.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("error validating client certificate: %w", err)
	}

	res, err := e.query.Eval(ctx, rego.EvalInput(e.newInput(req, isValid)))
	if err != nil {
		return nil, fmt.Errorf("error evaluating rego policy: %w", err)
	}

	deny := getDenyVar(res[0].Bindings.WithoutWildcards())
	if len(deny) > 0 {
		return &deny[0], nil
	}

	evalResult := &Result{
		MatchingPolicy: getMatchingPolicy(res[0].Bindings.WithoutWildcards(), e.policies),
		Headers:        getHeadersVar(res[0].Bindings.WithoutWildcards()),
	}

	allow := getAllowVar(res[0].Bindings.WithoutWildcards())
	// evaluate any custom policies
	if allow {
		for _, src := range req.CustomPolicies {
			cres, err := e.custom.Evaluate(ctx, &CustomEvaluatorRequest{
				RegoPolicy: src,
				HTTP:       req.HTTP,
				Session:    req.Session,
			})
			if err != nil {
				return nil, err
			}
			allow = allow && (cres.Allowed && !cres.Denied)
			if cres.Reason != "" {
				evalResult.Message = cres.Reason
			}
			for k, v := range cres.Headers {
				evalResult.Headers[k] = v
			}
		}
	}
	if allow {
		evalResult.Status = http.StatusOK
		evalResult.Message = http.StatusText(http.StatusOK)
		return evalResult, nil
	}

	if req.Session.ID == "" {
		evalResult.Status = http.StatusUnauthorized
		evalResult.Message = "login required"
		return evalResult, nil
	}

	evalResult.Status = http.StatusForbidden
	if evalResult.Message == "" {
		evalResult.Message = http.StatusText(http.StatusForbidden)
	}
	return evalResult, nil
}

func getJWK(options *config.Options) (*jose.JSONWebKey, error) {
	var decodedCert []byte
	// if we don't have a signing key, generate one
	if options.SigningKey == "" {
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
		decodedCert, err = base64.StdEncoding.DecodeString(options.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("bad signing key: %w", err)
		}
	}
	signingKeyAlgorithm := options.SigningKeyAlgorithm
	if signingKeyAlgorithm == "" {
		signingKeyAlgorithm = string(jose.ES256)
	}

	jwk, err := cryptutil.PrivateJWKFromBytes(decodedCert, jose.SignatureAlgorithm(signingKeyAlgorithm))
	if err != nil {
		return nil, fmt.Errorf("couldn't generate signing key: %w", err)
	}
	log.Info().Str("Algorithm", jwk.Algorithm).
		Str("KeyID", jwk.KeyID).
		Interface("Public Key", jwk.Public()).
		Msg("authorize: signing key")

	return jwk, nil
}

type input struct {
	HTTP                     RequestHTTP    `json:"http"`
	Session                  RequestSession `json:"session"`
	IsValidClientCertificate bool           `json:"is_valid_client_certificate"`
}

func (e *Evaluator) newInput(req *Request, isValidClientCertificate bool) *input {
	i := new(input)
	i.HTTP = req.HTTP
	i.Session = req.Session
	i.IsValidClientCertificate = isValidClientCertificate
	return i
}

// Result is the result of evaluation.
type Result struct {
	Status         int
	Message        string
	Headers        map[string]string
	MatchingPolicy *config.Policy
}

func getMatchingPolicy(vars rego.Vars, policies []config.Policy) *config.Policy {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return nil
	}

	idx, err := strconv.Atoi(fmt.Sprint(result["route_policy_idx"]))
	if err != nil {
		return nil
	}

	if idx >= len(policies) {
		return nil
	}

	return &policies[idx]
}

func getAllowVar(vars rego.Vars) bool {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return false
	}

	allow, ok := result["allow"].(bool)
	if !ok {
		return false
	}
	return allow
}

func getDenyVar(vars rego.Vars) []Result {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return nil
	}

	denials, ok := result["deny"].([]interface{})
	if !ok {
		return nil
	}

	results := make([]Result, 0, len(denials))
	for _, denial := range denials {
		denial, ok := denial.([]interface{})
		if !ok || len(denial) != 2 {
			continue
		}

		status, err := strconv.Atoi(fmt.Sprint(denial[0]))
		if err != nil {
			log.Error().Err(err).Msg("invalid type in deny")
			continue
		}
		msg := fmt.Sprint(denial[1])

		results = append(results, Result{
			Status:  status,
			Message: msg,
		})
	}
	return results
}

func getHeadersVar(vars rego.Vars) map[string]string {
	headers := make(map[string]string)

	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return headers
	}

	m, ok := result["identity_headers"].(map[string]interface{})
	if !ok {
		return headers
	}

	for k, v := range m {
		headers[k] = fmt.Sprint(v)
	}

	return headers
}
