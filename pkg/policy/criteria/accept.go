package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var acceptBody = ast.Body{
	ast.MustParseExpr(`v := true`),
}

type acceptCriterion struct {
	g *Generator
}

func (acceptCriterion) Names() []string {
	return []string{"accept"}
}

func (c acceptCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := c.g.NewRule("accept")
	rule.Head.Value = ast.VarTerm("v")
	rule.Body = acceptBody
	return rule, nil, nil
}

// Accept returns a Criterion which always returns true.
func Accept(generator *Generator) Criterion {
	return acceptCriterion{g: generator}
}

func init() {
	Register(Accept)
}
