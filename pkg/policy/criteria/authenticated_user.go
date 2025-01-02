package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var authenticatedUserBody = ast.Body{
	ast.MustParseExpr(`session := get_session(input.session.id)`),
	ast.MustParseExpr(`session.user_id != null`),
	ast.MustParseExpr(`session.user_id != ""`),
}

type authenticatedUserCriterion struct {
	g *Generator
}

func (authenticatedUserCriterion) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (authenticatedUserCriterion) Name() string {
	return "authenticated_user"
}

func (c authenticatedUserCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonUserOK, ReasonUserUnauthorized,
		authenticatedUserBody)
	return rule, []*ast.Rule{rules.GetSession()}, nil
}

// AuthenticatedUser returns a Criterion which returns true if the current user is logged in.
func AuthenticatedUser(generator *Generator) Criterion {
	return authenticatedUserCriterion{g: generator}
}

func init() {
	Register(AuthenticatedUser)
}
