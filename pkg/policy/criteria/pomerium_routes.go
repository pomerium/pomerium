package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

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
	r1 := c.g.NewRule(c.Name())
	r1.Head.Value = NewCriterionTerm(true, ReasonPomeriumRoute)
	r1.Body = ast.Body{
		ast.MustParseExpr(`session := get_session(input.session.id)`),
		ast.MustParseExpr(`session.id != ""`),
		ast.MustParseExpr(`contains(input.http.url, "/.pomerium/")`),
	}

	r2 := c.g.NewRule(c.Name())
	r2.Head.Value = NewCriterionTerm(true, ReasonPomeriumRoute)
	r2.Body = ast.Body{
		ast.MustParseExpr(`contains(input.http.url, "/.pomerium/")`),
		ast.MustParseExpr(`not contains(input.http.url, "/.pomerium/jwt")`),
		ast.MustParseExpr(`not contains(input.http.url, "` + urlutil.WebAuthnURLPath + `")`),
	}
	r1.Else = r2

	r3 := c.g.NewRule(c.Name())
	r3.Head.Value = NewCriterionTerm(false, ReasonUserUnauthenticated)
	r3.Body = ast.Body{
		ast.MustParseExpr(`contains(input.http.url, "/.pomerium/")`),
	}
	r2.Else = r3

	r4 := c.g.NewRule(c.Name())
	r4.Head.Value = NewCriterionTerm(false, ReasonNonPomeriumRoute)
	r3.Else = r4

	return r1, []*ast.Rule{
		rules.GetSession(),
	}, nil
}

// PomeriumRoutes returns a Criterion on that allows access to pomerium routes.
func PomeriumRoutes(generator *Generator) Criterion {
	return pomeriumRoutesCriterion{g: generator}
}

func init() {
	Register(PomeriumRoutes)
}
