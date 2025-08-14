package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type sourceIPCriterion struct {
	g *Generator
}

func (c sourceIPCriterion) DataType() CriterionDataType { return CriterionDataTypeStringMatcher }

func (c sourceIPCriterion) Name() string { return "source_ip" }

func (c sourceIPCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	ref := ast.RefTerm(ast.VarTerm("input"), ast.VarTerm("http"), ast.VarTerm("ip"))
	err := matchString(&body, ref, data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonSourceIPOK, ReasonSourceIPUnauthorized,
		body)

	return rule, nil, nil
}

// SourceIP returns a Criterion which matches source IP address.
func SourceIP(generator *Generator) Criterion {
	return sourceIPCriterion{g: generator}
}

func init() {
	Register(SourceIP)
}
