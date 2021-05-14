package generator

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// A Criterion generates rego rules based on data.
type Criterion interface {
	Names() []string
	GenerateRule(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error)
}

// A CriterionConstructor is a function which returns a Criterion for a Generator.
type CriterionConstructor func(*Generator) Criterion

// A criterionFunc is a criterion implemented as a function and a list of names.
type criterionFunc struct {
	names        []string
	generateRule func(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error)
}

// Names returns the names of the criterion.
func (c criterionFunc) Names() []string {
	return c.names
}

// GenerateRule calls the underlying generateRule function.
func (c criterionFunc) GenerateRule(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error) {
	return c.generateRule(subPath, data)
}

// NewCriterionFunc creates a new Criterion from a function.
func NewCriterionFunc(
	names []string,
	f func(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error),
) Criterion {
	return criterionFunc{
		names:        names,
		generateRule: f,
	}
}
