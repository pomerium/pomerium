// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/log"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator struct {
	rego     *rego.Rego
	clientCA string
}

// New creates a new Evaluator.
func New(options *config.Options) (*Evaluator, error) {
	e := &Evaluator{}
	if options.ClientCA != "" {
		e.clientCA = options.ClientCA
	} else if options.ClientCAFile != "" {
		bs, err := ioutil.ReadFile(options.ClientCAFile)
		if err != nil {
			return nil, err
		}
		e.clientCA = string(bs)
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

	return e, nil
}

// Evaluate evaluates the policy against the request.
func (e *Evaluator) Evaluate(ctx context.Context, req *Request) (*Result, error) {
	query, err := e.rego.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("error preparing rego query: %w", err)
	}

	isValid, err := isValidClientCertificate(e.clientCA, req.HTTP.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("error validating client certificate: %w", err)
	}

	res, err := query.Eval(ctx, rego.EvalInput(newInput(req, isValid)))
	if err != nil {
		return nil, fmt.Errorf("error evaluating rego policy: %w", err)
	}

	log.Info().
		Interface("session", req.Session).
		Interface("databroker_data", req.DataBrokerData).
		Msg("EVALUATE")

	deny := getDenyVar(res[0].Bindings.WithoutWildcards())
	if len(deny) > 0 {
		return &deny[0], nil
	}

	allow := getAllowVar(res[0].Bindings.WithoutWildcards())
	if allow {
		return &Result{
			Status:  http.StatusOK,
			Message: "OK",
		}, nil
	}

	if req.Session.ID == "" {
		return &Result{
			Status:  http.StatusUnauthorized,
			Message: "login required",
		}, nil
	}

	return &Result{
		Status:  http.StatusForbidden,
		Message: "forbidden",
	}, nil
}

type input struct {
	DataBrokerData           DataBrokerData `json:"databroker_data"`
	HTTP                     RequestHTTP    `json:"http"`
	Session                  RequestSession `json:"session"`
	IsValidClientCertificate bool           `json:"is_valid_client_certificate"`
}

func newInput(req *Request, isValidClientCertificate bool) *input {
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
	Status  int
	Message string
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

	var results []Result
	for _, denial := range denials {
		denial, ok := denial.([]interface{})
		if !ok || len(denial) < 2 {
			continue
		}

		status, err := strconv.Atoi(fmt.Sprint(denial[0]))
		if err != nil {
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
