package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type httpMethodCriterion struct {
	g *Generator
}

func (httpMethodCriterion) DataType() CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (httpMethodCriterion) Name() string {
	return "http_method"
}

func (c httpMethodCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	ref := ast.RefTerm(ast.VarTerm("input"), ast.VarTerm("http"), ast.VarTerm("method"))
	err := matchString(&body, ref, data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonHTTPMethodOK, ReasonHTTPMethodUnauthorized,
		body)

	return rule, nil, nil
}

// HTTPMethod returns a Criterion which matches an HTTP method.
func HTTPMethod(generator *Generator) Criterion {
	return httpMethodCriterion{g: generator}
}

func init() {
	Register(HTTPMethod)
}
