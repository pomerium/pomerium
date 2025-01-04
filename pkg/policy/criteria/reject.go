package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type rejectMatcher struct {
	g *Generator
}

func (rejectMatcher) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (rejectMatcher) Name() string {
	return "reject"
}

func (m rejectMatcher) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := m.g.NewRule("reject")
	rule.Head.Value = NewCriterionTerm(false, ReasonReject)
	rule.Body = ast.Body{ast.NewExpr(ast.BooleanTerm(true))}
	return rule, nil, nil
}

// Reject returns a Criterion which always returns false.
func Reject(generator *Generator) Criterion {
	return rejectMatcher{g: generator}
}

func init() {
	Register(Reject)
}
