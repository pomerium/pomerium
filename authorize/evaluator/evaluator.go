// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/config"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator struct {
	rego *rego.Rego
}

// NewEvaluator creates a new Evaluator.
func NewEvaluator(options *config.Options) *Evaluator {
	return &Evaluator{}
}

// Evaluate evaluates the policy agains the request.
func (e *Evaluator) Evaluate(ctx context.Context, req *Request) (*Result, error) {
	query, err := e.rego.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("error preparing rego query: %w", err)
	}

	res, err := query.Eval(ctx, rego.EvalInput(req))
	if err != nil {
		return nil, fmt.Errorf("error evaluating rego policy: %w", err)
	}

	return nil, fmt.Errorf("not implemented")
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
