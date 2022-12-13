package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var pomeriumRoutesBody = ast.Body{
	ast.MustParseExpr(`
		contains(input.http.url, "/.pomerium/")
	`),
	ast.MustParseExpr(`
		not contains(input.http.url, "/.pomerium/jwt")
	`),
}

type pomeriumRoutesCriterion struct {
	g *Generator
}

func (pomeriumRoutesCriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (pomeriumRoutesCriterion) Name() string {
	return "pomerium_routes"
}

func (c pomeriumRoutesCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := NewCriterionRule(c.g, c.Name(),
		ReasonPomeriumRoute, ReasonNonPomeriumRoute,
		pomeriumRoutesBody)

	return rule, nil, nil
}

// PomeriumRoutes returns a Criterion on that allows access to pomerium routes.
func PomeriumRoutes(generator *Generator) Criterion {
	return pomeriumRoutesCriterion{g: generator}
}

func init() {
	Register(PomeriumRoutes)
}
