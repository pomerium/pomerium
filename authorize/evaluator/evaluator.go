// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

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
		custom:   NewCustomEvaluator(store),
		policies: options.GetAllPolicies(),
		store:    store,
	}
	jwk, err := getJWK(options)
	if err != nil {
		return nil, fmt.Errorf("authorize: couldn't create signer: %w", err)
	}

	authzPolicy, err := readPolicy()
	if err != nil {
		return nil, fmt.Errorf("error loading rego policy: %w", err)
	}

	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid authenticate URL: %w", err)
	}

	store.UpdateIssuer(authenticateURL.Host)
	store.UpdateGoogleCloudServerlessAuthenticationServiceAccount(
		options.GetGoogleCloudServerlessAuthenticationServiceAccount(),
	)
	store.UpdateJWTClaimHeaders(options.JWTClaimsHeaders)
	store.UpdateRoutePolicies(options.GetAllPolicies())
	store.UpdateSigningKey(jwk)

	e.rego = rego.New(
		rego.Store(store),
		rego.Module("pomerium.authz", string(authzPolicy)),
		rego.Query("result = data.pomerium.authz"),
		getGoogleCloudServerlessHeadersRegoOption,
		store.GetDataBrokerRecordOption(),
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
	evalResult.DataBrokerServerVersion, evalResult.DataBrokerRecordVersion = getDataBrokerVersions(
		res[0].Bindings,
	)

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
	log.Info(context.TODO()).Str("Algorithm", jwk.Algorithm).
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
