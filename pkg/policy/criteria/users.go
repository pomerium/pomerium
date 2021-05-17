package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

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
}

type usersCriterion struct {
	g *Generator
}

func (usersCriterion) Names() []string {
	return []string{"user", "users"}
}

func (c usersCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("users")
	r.Body = append(r.Body, ast.Assign.Expr(ast.VarTerm("rule_data"), ast.NewTerm(data.RegoValue())))
	r.Body = append(r.Body, usersBody...)

	switch data.(type) {
	case parser.String:
		r.Body = append(r.Body, ast.MustParseExpr(`user_id = rule_data`))
	default:
		return nil, nil, fmt.Errorf("unsupported value type: %T", data)
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
