package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var rejectBody = ast.Body{
	ast.MustParseExpr(`v := false`),
}

type rejectMatcher struct {
	g *Generator
}

func (rejectMatcher) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (rejectMatcher) Names() []string {
	return []string{"reject"}
}

func (m rejectMatcher) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := m.g.NewRule("reject")
	rule.Head.Value = ast.VarTerm("v")
	rule.Body = rejectBody
	return rule, nil, nil
}

// Reject returns a Criterion which always returns false.
func Reject(generator *Generator) Criterion {
	return rejectMatcher{g: generator}
}

func init() {
	Register(Reject)
}
