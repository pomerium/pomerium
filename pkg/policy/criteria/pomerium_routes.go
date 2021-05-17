package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var pomeriumRoutesBody = ast.Body{
	ast.MustParseExpr(`
		contains(input.http.url, "/.pomerium/")
	`),
}

type pomeriumRoutesCriterion struct {
	g *Generator
}

func (pomeriumRoutesCriterion) Names() []string {
	return []string{"pomerium_routes"}
}

func (c pomeriumRoutesCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("pomerium_routes")
	r.Body = append(r.Body, pomeriumRoutesBody...)

	return r, nil, nil
}

// PomeriumRoutes returns a Criterion on that allows access to pomerium routes.
func PomeriumRoutes(generator *Generator) Criterion {
	return pomeriumRoutesCriterion{g: generator}
}

func init() {
	Register(PomeriumRoutes)
}
