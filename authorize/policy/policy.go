// Package policy implements a policy evaluator for routes.
package policy

//go:generate go run github.com/mjibson/esc -o=files.go -pkg=policy -prefix=files -private files

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/pomerium/pomerium/config"
)

// An Evaluator evaluates policies using OPA Rego.
type Evaluator struct {
	rego *rego.Rego
}

// Evaluate evaluates the policy against the passed in input.
func (pe *Evaluator) Evaluate(ctx context.Context, input *EvaluatorInput) (*EvaluatorOutput, error) {
	q, err := pe.rego.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("error preparing rego query: %w", err)
	}

	res, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("error evaluating rego query: %w", err)
	}

	denials := res[0].Bindings.WithoutWildcards()["denials"].([]interface{})
	if len(denials) == 0 {
		return &EvaluatorOutput{
			Status:  http.StatusOK,
			Message: "OK",
		}, nil
	}

	denial, ok := denials[0].([]interface{})
	if !ok || len(denial) != 2 {
		return nil, fmt.Errorf("invalid result type from OPA evaluation: %T", denial)
	}

	var output EvaluatorOutput
	output.Status, _ = strconv.Atoi(fmt.Sprint(denial[0]))
	output.Message = fmt.Sprint(denial[1])
	return &output, nil
}

// EvaluatorInput is the input used for policy evaluation.
type EvaluatorInput struct {
	User              *EvaluatorUser                    `json:"user"`
	DataBrokerData    map[string]map[string]interface{} `json:"databroker_data"`
	ImpersonateEmail  string                            `json:"impersonate_email"`
	ImpersonateGroups []string                          `json:"impersonate_groups"`

	// require_client_certificate
	IsValidClientCertificate bool `json:"is_valid_client_certificate"`
}

// EvaluatorOutput is the result of evaluating the policy.
type EvaluatorOutput struct {
	Status  int
	Message string
}

// EvaluatorUser is the user information for policy evaluation.
type EvaluatorUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// GetEvaluator gets a new Evaluator for the given policy.
func GetEvaluator(policy *config.Policy) *Evaluator {
	data := map[string]interface{}{}
	data["allowed_domains"] = policy.AllowedDomains
	data["allowed_groups"] = policy.AllowedGroups
	data["allowed_emails"] = policy.AllowedUsers

	query := "denials = set()"
	if !policy.AllowPublicUnauthenticatedAccess {
		query += " | data.pomerium.require_user.deny"
	}
	if policy.ClientCertificate != nil {
		query += " | data.pomerium.require_client_certificate.deny"
	}
	if len(policy.AllowedDomains) > 0 {
		query += " | data.pomerium.require_domain.deny"
	}
	if len(policy.AllowedUsers) > 0 {
		query += " | data.pomerium.require_email.deny"
	}
	if len(policy.AllowedGroups) > 0 {
		query += " | data.pomerium.require_group.deny"
	}

	r := rego.New(
		rego.Store(inmem.NewFromObject(data)),
		rego.Module("pomerium.require_client_certificate", _escFSMustString(false, "/require_client_certificate.rego")),
		rego.Module("pomerium.require_domain", _escFSMustString(false, "/require_domain.rego")),
		rego.Module("pomerium.require_email", _escFSMustString(false, "/require_email.rego")),
		rego.Module("pomerium.require_group", _escFSMustString(false, "/require_group.rego")),
		rego.Module("pomerium.require_user", _escFSMustString(false, "/require_user.rego")),
		rego.Query(query),
	)
	return &Evaluator{rego: r}
}
