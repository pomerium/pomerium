// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
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
	"github.com/open-policy-agent/opa/storage/inmem"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/log"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator struct {
	rego  *rego.Rego
	query rego.PreparedEvalQuery

	clientCA         string
	authenticateHost string
	jwk              interface{}
}

// New creates a new Evaluator.
func New(options *config.Options) (*Evaluator, error) {
	e := &Evaluator{
		authenticateHost: options.AuthenticateURL.Host,
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
		keyBytes, err := cryptutil.DecodePrivateKey((decodedCert))
		if err != nil {
			return nil, fmt.Errorf("authorize: couldn't generate signing key: %w", err)
		}
		e.jwk = keyBytes
	}

	authzPolicy, err := readPolicy("/authz.rego")
	if err != nil {
		return nil, fmt.Errorf("error loading rego policy: %w", err)
	}

	e.rego = rego.New(
		rego.Store(inmem.NewFromObject(map[string]interface{}{
			"admins":         options.Administrators,
			"route_policies": options.Policies,
		})),
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

	signedJWT, err := e.getSignedJWT(req)
	if err != nil {
		return nil, fmt.Errorf("error signing JWT: %w", err)
	}

	allow := allowed(res[0].Bindings.WithoutWildcards())
	if allow {
		return &Result{
			Status:    http.StatusOK,
			Message:   "OK",
			SignedJWT: signedJWT,
		}, nil
	}

	if req.Session.ID == "" {
		return &Result{
			Status:    http.StatusUnauthorized,
			Message:   "login required",
			SignedJWT: signedJWT,
		}, nil
	}

	return &Result{
		Status:    http.StatusForbidden,
		Message:   "forbidden",
		SignedJWT: signedJWT,
	}, nil
}

func (e *Evaluator) getSignedJWT(req *Request) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       e.jwk,
	}, nil)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"iss": e.authenticateHost,
	}
	if u, err := url.Parse(req.HTTP.URL); err == nil {
		payload["aud"] = u.Hostname()
	}
	if s, ok := req.DataBrokerData.Get("type.googleapis.com/session.Session", req.Session.ID).(*session.Session); ok {
		if tm, err := ptypes.Timestamp(s.GetIdToken().GetExpiresAt()); err == nil {
			payload["exp"] = tm.Unix()
		}
		if tm, err := ptypes.Timestamp(s.GetIdToken().GetIssuedAt()); err == nil {
			payload["iat"] = tm.Unix()
		}
		if u, ok := req.DataBrokerData.Get("type.googleapis.com/user.User", s.GetUserId()).(*user.User); ok {
			payload["sub"] = u.GetId()
			payload["email"] = u.GetEmail()
		}
		if du, ok := req.DataBrokerData.Get("type.googleapis.com/directory.User", s.GetUserId()).(*directory.User); ok {
			payload["groups"] = du.GetGroups()
		}
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
	DataBrokerData           DataBrokerData `json:"databroker_data"`
	HTTP                     RequestHTTP    `json:"http"`
	Session                  RequestSession `json:"session"`
	IsValidClientCertificate bool           `json:"is_valid_client_certificate"`
}

func (e *Evaluator) newInput(req *Request, isValidClientCertificate bool) *input {
	i := new(input)
	i.DataBrokerData = req.DataBrokerData
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
	Status    int
	Message   string
	SignedJWT string
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
