// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/pomerium/pomerium/config"
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

	isValid, err := isValidClientCertificate(e.clientCA, req.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("error validating client certificate: %w", err)
	}

	res, err := query.Eval(ctx, rego.EvalInput(&input{
		User:                     req.User,
		HTTP:                     req.HTTP,
		IsValidClientCertificate: isValid,
	}))
	if err != nil {
		return nil, fmt.Errorf("error evaluating rego policy: %w", err)
	}

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

	if req.User == nil {
		return &Result{
			Status:  http.StatusUnauthorized,
			Message: "login required",
		}, nil
	}

	return &Result{
		Status:  http.StatusForbidden,
		Message: "unauthorized",
	}, nil
}

type input struct {
	User                     *User        `json:"user"`
	HTTP                     *HTTPDetails `json:"http"`
	IsValidClientCertificate bool         `json:"is_valid_client_certificate"`
}

// A Request represents an evaluable request with an associated user, device,
// and request context.
type Request struct {
	// User contains the user details.
	User *User `json:"user"`
	// HTTP contains the http request details.
	HTTP *HTTPDetails `json:"http"`
	// ClientCertificate is the PEM-encoded public certificate used for the user's TLS connection.
	ClientCertificate string `json:"client_certificate"`

	// DataBrokerData is the generic data that comes from the databroker as a map of id => struct.
	DataBrokerData map[string]map[string]interface{} `json:"databroker_data"`
	// ImpersonateEmail is the email the user can impersonate.
	ImpersonateEmail string `json:"impersonate_email"`
	// ImpersonateGroups are the list of groups the user can impersonate.
	ImpersonateGroups []string `json:"impersonate_groups"`
}

// The HTTPDetails are the http request details needed for policy decisions.
type HTTPDetails struct {
	Method  string
	URL     string
	Headers map[string]string
}

// User is the user making the request.
type User struct {
	ID    string
	Email string
}

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
