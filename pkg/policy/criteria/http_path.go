package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type httpPathCriterion struct {
	g *Generator
}

func (httpPathCriterion) DataType() CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (httpPathCriterion) Name() string {
	return "http_path"
}

func (c httpPathCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	ref := ast.RefTerm(ast.VarTerm("input"), ast.VarTerm("http"), ast.VarTerm("path"))
	err := matchString(&body, ref, data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonHTTPPathOK, ReasonHTTPPathUnauthorized,
		body)

	return rule, nil, nil
}

// HTTPPath returns a Criterion which matches an HTTP path.
func HTTPPath(generator *Generator) Criterion {
	return httpPathCriterion{g: generator}
}

func init() {
	Register(HTTPPath)
}
