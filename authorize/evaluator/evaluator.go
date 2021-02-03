// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	directoryGroupTypeURL = "type.googleapis.com/directory.Group"
	directoryUserTypeURL  = "type.googleapis.com/directory.User"
	serviceAccountTypeURL = "type.googleapis.com/user.ServiceAccount"
	sessionTypeURL        = "type.googleapis.com/session.Session"
	userTypeURL           = "type.googleapis.com/user.User"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator struct {
	custom   *CustomEvaluator
	rego     *rego.Rego
	query    rego.PreparedEvalQuery
	policies []config.Policy
	store    *Store

	authenticateHost string
	jwk              *jose.JSONWebKey
	signer           jose.Signer
}

// New creates a new Evaluator.
func New(options *config.Options, store *Store) (*Evaluator, error) {
	e := &Evaluator{
		custom:           NewCustomEvaluator(store.opaStore),
		authenticateHost: options.AuthenticateURL.Host,
		policies:         options.GetAllPolicies(),
		store:            store,
	}
	var err error
	e.signer, e.jwk, err = newSigner(options)
	if err != nil {
		return nil, fmt.Errorf("authorize: couldn't create signer: %w", err)
	}

	authzPolicy, err := readPolicy("/authz.rego")
	if err != nil {
		return nil, fmt.Errorf("error loading rego policy: %w", err)
	}

	store.UpdateRoutePolicies(options.GetAllPolicies())

	e.rego = rego.New(
		rego.Store(store.opaStore),
		rego.Module("pomerium.authz", string(authzPolicy)),
		rego.Query("result = data.pomerium.authz"),
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

	payload := e.JWTPayload(req)

	signedJWT, err := e.SignedJWT(payload)
	if err != nil {
		return nil, fmt.Errorf("error signing JWT: %w", err)
	}

	evalResult := &Result{
		MatchingPolicy: getMatchingPolicy(res[0].Bindings.WithoutWildcards(), e.policies),
		SignedJWT:      signedJWT,
	}
	if e, ok := payload["email"].(string); ok {
		evalResult.UserEmail = e
	}
	if gs, ok := payload["groups"].([]string); ok {
		evalResult.UserGroups = gs
	}

	allow := allowed(res[0].Bindings.WithoutWildcards())
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

// ParseSignedJWT parses the input signature and return its payload.
func (e *Evaluator) ParseSignedJWT(signature string) ([]byte, error) {
	object, err := jose.ParseSigned(signature)
	if err != nil {
		return nil, err
	}
	return object.Verify(e.jwk.Public())
}

// JWTPayload returns the JWT payload for a request.
func (e *Evaluator) JWTPayload(req *Request) map[string]interface{} {
	payload := map[string]interface{}{
		"iss": e.authenticateHost,
	}
	req.fillJWTPayload(e.store, payload)
	return payload
}

func newSigner(options *config.Options) (jose.Signer, *jose.JSONWebKey, error) {
	var decodedCert []byte
	// if we don't have a signing key, generate one
	if options.SigningKey == "" {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't generate signing key: %w", err)
		}
		decodedCert, err = cryptutil.EncodePrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("bad signing key: %w", err)
		}
	} else {
		var err error
		decodedCert, err = base64.StdEncoding.DecodeString(options.SigningKey)
		if err != nil {
			return nil, nil, fmt.Errorf("bad signing key: %w", err)
		}
	}
	signingKeyAlgorithm := options.SigningKeyAlgorithm
	if signingKeyAlgorithm == "" {
		signingKeyAlgorithm = string(jose.ES256)
	}

	jwk, err := cryptutil.PrivateJWKFromBytes(decodedCert, jose.SignatureAlgorithm(signingKeyAlgorithm))
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't generate signing key: %w", err)
	}
	log.Info().Str("Algorithm", jwk.Algorithm).
		Str("KeyID", jwk.KeyID).
		Interface("Public Key", jwk.Public()).
		Msg("authorize: signing key")

	signerOpt := &jose.SignerOptions{}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk,
	}, signerOpt.WithHeader("kid", jwk.KeyID))
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create signer: %w", err)
	}
	return signer, jwk, nil
}

// SignedJWT returns the signature of given request.
func (e *Evaluator) SignedJWT(payload map[string]interface{}) (string, error) {
	if e.signer == nil {
		return "", errors.New("evaluator: signer cannot be nil")
	}

	bs, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	jws, err := e.signer.Sign(bs)
	if err != nil {
		return "", err
	}

	return jws.CompactSerialize()
}

type input struct {
	DataBrokerData           dataBrokerDataInput `json:"databroker_data"`
	HTTP                     RequestHTTP         `json:"http"`
	Session                  RequestSession      `json:"session"`
	IsValidClientCertificate bool                `json:"is_valid_client_certificate"`
}

type dataBrokerDataInput struct {
	Session interface{} `json:"session,omitempty"`
	User    interface{} `json:"user,omitempty"`
	Groups  interface{} `json:"groups,omitempty"`
}

func (e *Evaluator) newInput(req *Request, isValidClientCertificate bool) *input {
	i := new(input)
	i.DataBrokerData.Session = e.store.GetRecordData(sessionTypeURL, req.Session.ID)
	if i.DataBrokerData.Session == nil {
		i.DataBrokerData.Session = e.store.GetRecordData(serviceAccountTypeURL, req.Session.ID)
	}
	var userIDs []string
	if obj, ok := i.DataBrokerData.Session.(interface{ GetUserId() string }); ok && obj.GetUserId() != "" {
		userIDs = append(userIDs, obj.GetUserId())
	}
	if obj, ok := i.DataBrokerData.Session.(interface{ GetImpersonateUserId() string }); ok && obj.GetImpersonateUserId() != "" {
		userIDs = append(userIDs, obj.GetImpersonateUserId())
	}

	for _, userID := range userIDs {
		i.DataBrokerData.User = e.store.GetRecordData(userTypeURL, userID)

		user, ok := e.store.GetRecordData(directoryUserTypeURL, userID).(*directory.User)
		if ok {
			var groups []string
			for _, groupID := range user.GetGroupIds() {
				if dg, ok := e.store.GetRecordData(directoryGroupTypeURL, groupID).(*directory.Group); ok {
					if dg.Name != "" {
						groups = append(groups, dg.Name)
					}
					if dg.Email != "" {
						groups = append(groups, dg.Email)
					}
				}
			}
			groups = append(groups, user.GetGroupIds()...)
			i.DataBrokerData.Groups = groups
		}
	}
	i.HTTP = req.HTTP
	i.Session = req.Session
	i.IsValidClientCertificate = isValidClientCertificate
	return i
}

// Result is the result of evaluation.
type Result struct {
	Status         int
	Message        string
	SignedJWT      string
	MatchingPolicy *config.Policy

	UserEmail  string
	UserGroups []string
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

func allowed(vars rego.Vars) bool {
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
