package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var usersBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		user := get_user(session)
	`),
	ast.MustParseExpr(`
		user_id := user.id
	`),
}

type usersCriterion struct {
	g *Generator
}

func (usersCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (usersCriterion) Name() string {
	return "user"
}

func (c usersCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("users")
	r.Body = append(r.Body, usersBody...)

	err := matchString(&r.Body, ast.VarTerm("user_id"), data)
	if err != nil {
		return nil, nil, err
	}

	return r, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.GetUserEmail(),
	}, nil
}

// UserIDs returns a Criterion on a user's id.
func UserIDs(generator *Generator) Criterion {
	return usersCriterion{g: generator}
}

func init() {
	Register(UserIDs)
}
