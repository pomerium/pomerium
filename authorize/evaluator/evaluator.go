// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const (
	sessionTypeURL        = "type.googleapis.com/session.Session"
	userTypeURL           = "type.googleapis.com/user.User"
	directoryUserTypeURL  = "type.googleapis.com/directory.User"
	directoryGroupTypeURL = "type.googleapis.com/directory.Group"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator struct {
	custom   *CustomEvaluator
	rego     *rego.Rego
	query    rego.PreparedEvalQuery
	policies []config.Policy

	clientCA         string
	authenticateHost string
	jwk              interface{}
	kid              string
}

// New creates a new Evaluator.
func New(options *config.Options, store *Store) (*Evaluator, error) {
	e := &Evaluator{
		custom:           NewCustomEvaluator(store.opaStore),
		authenticateHost: options.AuthenticateURL.Host,
		policies:         options.Policies,
	}
	if options.ClientCA != "" {
		e.clientCA = options.ClientCA
	} else if options.ClientCAFile != "" {
		bs, err := ioutil.ReadFile(options.ClientCAFile)
		if err != nil {
			return nil, err
		}
		e.clientCA = string(bs)
	}

	if options.SigningKey == "" {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, fmt.Errorf("authorize: couldn't generate signing key: %w", err)
		}
		e.jwk = key
		pubKeyBytes, err := cryptutil.EncodePublicKey(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authorize: encode public key: %w", err)
		}
		log.Info().Interface("PublicKey", pubKeyBytes).Msg("authorize: ecdsa public key")
	} else {
		decodedCert, err := base64.StdEncoding.DecodeString(options.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("authorize: failed to decode certificate cert %v: %w", decodedCert, err)
		}
		key, err := cryptutil.DecodePrivateKey(decodedCert)
		if err != nil {
			return nil, fmt.Errorf("authorize: couldn't generate signing key: %w", err)
		}
		e.jwk = key
		jwk, err := cryptutil.PublicJWKFromBytes(decodedCert, jose.ES256)
		if err != nil {
			return nil, fmt.Errorf("authorize: failed to convert jwk: %w", err)
		}
		e.kid = jwk.KeyID
	}

	authzPolicy, err := readPolicy("/authz.rego")
	if err != nil {
		return nil, fmt.Errorf("error loading rego policy: %w", err)
	}

	store.UpdateAdmins(options.Administrators)
	store.UpdateRoutePolicies(options.Policies)

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
	isValid, err := isValidClientCertificate(e.clientCA, req.HTTP.ClientCertificate)
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
		evalResult.Message = "OK"
		return evalResult, nil
	}

	if req.Session.ID == "" {
		evalResult.Status = http.StatusUnauthorized
		evalResult.Message = "login required"
		return evalResult, nil
	}

	evalResult.Status = http.StatusForbidden
	if evalResult.Message == "" {
		evalResult.Message = "forbidden"
	}
	return evalResult, nil
}

// ParseSignedJWT parses the input signature and return its payload.
func (e *Evaluator) ParseSignedJWT(signature string) ([]byte, error) {
	object, err := jose.ParseSigned(signature)
	if err != nil {
		return nil, err
	}
	return object.Verify(&(e.jwk.(*ecdsa.PrivateKey).PublicKey))
}

// JWTPayload returns the JWT payload for a request.
func (e *Evaluator) JWTPayload(req *Request) map[string]interface{} {
	payload := map[string]interface{}{
		"iss": e.authenticateHost,
	}
	if u, err := url.Parse(req.HTTP.URL); err == nil {
		payload["aud"] = u.Hostname()
	}
	if s, ok := req.DataBrokerData.Get("type.googleapis.com/session.Session", req.Session.ID).(*session.Session); ok {
		payload["jti"] = s.GetId()
		if tm, err := ptypes.Timestamp(s.GetIdToken().GetExpiresAt()); err == nil {
			payload["exp"] = tm.Unix()
		}
		if tm, err := ptypes.Timestamp(s.GetIdToken().GetIssuedAt()); err == nil {
			payload["iat"] = tm.Unix()
		}
		if u, ok := req.DataBrokerData.Get("type.googleapis.com/user.User", s.GetUserId()).(*user.User); ok {
			payload["sub"] = u.GetId()
			payload["user"] = u.GetId()
			payload["email"] = u.GetEmail()
		}
		if du, ok := req.DataBrokerData.Get("type.googleapis.com/directory.User", s.GetUserId()).(*directory.User); ok {
			var groupNames []string
			for _, groupID := range du.GetGroupIds() {
				if dg, ok := req.DataBrokerData.Get("type.googleapis.com/directory.Group", groupID).(*directory.Group); ok {
					groupNames = append(groupNames, dg.Name)
				}
			}
			var groups []string
			groups = append(groups, du.GetGroupIds()...)
			groups = append(groups, groupNames...)
			payload["groups"] = groups
		}
	}
	return payload
}

// SignedJWT returns the signature of given request.
func (e *Evaluator) SignedJWT(payload map[string]interface{}) (string, error) {
	signerOpt := &jose.SignerOptions{}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       e.jwk,
	}, signerOpt.WithHeader("kid", e.kid))
	if err != nil {
		return "", err
	}

	bs, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	jws, err := signer.Sign(bs)
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
	i.DataBrokerData.Session = req.DataBrokerData.Get(sessionTypeURL, req.Session.ID)
	if obj, ok := i.DataBrokerData.Session.(interface{ GetUserId() string }); ok {
		i.DataBrokerData.User = req.DataBrokerData.Get(userTypeURL, obj.GetUserId())

		user, ok := req.DataBrokerData.Get(directoryUserTypeURL, obj.GetUserId()).(*directory.User)
		if ok {
			var groups []string
			for _, groupID := range user.GetGroupIds() {
				if dg, ok := req.DataBrokerData.Get(directoryGroupTypeURL, groupID).(*directory.Group); ok {
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

type (
	// Request is the request data used for the evaluator.
	Request struct {
		DataBrokerData DataBrokerData `json:"databroker_data"`
		HTTP           RequestHTTP    `json:"http"`
		Session        RequestSession `json:"session"`
		CustomPolicies []string
	}

	// RequestHTTP is the HTTP field in the request.
	RequestHTTP struct {
		Method            string            `json:"method"`
		URL               string            `json:"url"`
		Headers           map[string]string `json:"headers"`
		ClientCertificate string            `json:"client_certificate"`
	}

	// RequestSession is the session field in the request.
	RequestSession struct {
		ID                string   `json:"id"`
		ImpersonateEmail  string   `json:"impersonate_email"`
		ImpersonateGroups []string `json:"impersonate_groups"`
	}
)

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

// DataBrokerData stores the data broker data by type => id => record
type DataBrokerData map[string]map[string]interface{}

// Clear removes all the data for the given type URL from the databroekr data.
func (dbd DataBrokerData) Clear(typeURL string) {
	delete(dbd, typeURL)
}

// Get gets a record from the DataBrokerData.
func (dbd DataBrokerData) Get(typeURL, id string) interface{} {
	m, ok := dbd[typeURL]
	if !ok {
		return nil
	}
	return m[id]
}

// Update updates a record in the DataBrokerData.
func (dbd DataBrokerData) Update(record *databroker.Record) {
	db, ok := dbd[record.GetType()]
	if !ok {
		db = make(map[string]interface{})
		dbd[record.GetType()] = db
	}

	if record.GetDeletedAt() != nil {
		delete(db, record.GetId())
	} else {
		if obj, err := unmarshalAny(record.GetData()); err == nil {
			db[record.GetId()] = obj
		} else {
			log.Warn().Err(err).Msg("failed to unmarshal unknown any type")
			delete(db, record.GetId())
		}
	}
}

func unmarshalAny(any *anypb.Any) (proto.Message, error) {
	messageType, err := protoregistry.GlobalTypes.FindMessageByURL(any.GetTypeUrl())
	if err != nil {
		return nil, err
	}
	msg := proto.MessageV1(messageType.New())
	return msg, ptypes.UnmarshalAny(any, msg)
}
