package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type acceptCriterion struct {
	g *Generator
}

func (acceptCriterion) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (acceptCriterion) Name() string {
	return "accept"
}

func (c acceptCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := c.g.NewRule(c.Name())
	rule.Head.Value = NewCriterionTerm(true, ReasonAccept)
	rule.Body = ast.Body{ast.NewExpr(ast.BooleanTerm(true))}
	return rule, nil, nil
}

// Accept returns a Criterion which always returns true.
func Accept(generator *Generator) Criterion {
	return acceptCriterion{g: generator}
}

func init() {
	Register(Accept)
}
