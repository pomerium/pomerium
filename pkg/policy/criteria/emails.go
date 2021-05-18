package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var emailsBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		user := get_user(session)
	`),
	ast.MustParseExpr(`
		email := get_user_email(session, user)
	`),
}

type emailsCriterion struct {
	g *Generator
}

func (emailsCriterion) Names() []string {
	return []string{"email", "emails"}
}

func (c emailsCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("emails")
	r.Body = append(r.Body, ast.Assign.Expr(ast.VarTerm("rule_data"), ast.NewTerm(data.RegoValue())))
	r.Body = append(r.Body, emailsBody...)

	switch data.(type) {
	case parser.String:
		r.Body = append(r.Body, ast.MustParseExpr(`email == rule_data`))
	default:
		return nil, nil, fmt.Errorf("unsupported value type: %T", data)
	}

	return r, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.GetUserEmail(),
	}, nil
}

// Emails returns a Criterion on a user's email address.
func Emails(generator *Generator) Criterion {
	return emailsCriterion{g: generator}
}

func init() {
	Register(Emails)
}
