// Package mock implements the policy evaluator interface to make authorization
// decisions.
package mock

import (
	"context"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

var _ evaluator.Evaluator = &PolicyEvaluator{}

// PolicyEvaluator is the mock implementation of Evaluator
type PolicyEvaluator struct {
	IsAuthorizedResponse bool
	IsAuthorizedErr      error
	IsAdminResponse      bool
	IsAdminErr           error
	PutDataErr           error
}

// IsAuthorized is the mock implementation of IsAuthorized
func (pe PolicyEvaluator) IsAuthorized(ctx context.Context, input interface{}) (bool, error) {
	return pe.IsAuthorizedResponse, pe.IsAuthorizedErr
}

// IsAdmin is the mock implementation of IsAdmin
func (pe PolicyEvaluator) IsAdmin(ctx context.Context, input interface{}) (bool, error) {
	return pe.IsAdminResponse, pe.IsAdminErr
}

// PutData is the mock implementation of PutData
func (pe PolicyEvaluator) PutData(ctx context.Context, data map[string]interface{}) error {
	return pe.PutDataErr
}
