package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
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

func (emailsCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (emailsCriterion) Name() string {
	return "email"
}

func (c emailsCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("emails")
	r.Body = append(r.Body, emailsBody...)

	err := matchString(&r.Body, ast.VarTerm("email"), data)
	if err != nil {
		return nil, nil, err
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
