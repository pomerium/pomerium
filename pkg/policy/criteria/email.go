package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var emailBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		user := get_user(session)
	`),
	ast.MustParseExpr(`
		directory_user := get_directory_user(session)
	`),
	ast.MustParseExpr(`
		email := get_user_email(session, user, directory_user)
	`),
}

type emailCriterion struct {
	g *Generator
}

func (emailCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (emailCriterion) Name() string {
	return "email"
}

func (c emailCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	body = append(body, emailBody...)

	err := matchString(&body, ast.VarTerm("email"), data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonEmailOK, ReasonEmailUnauthorized,
		body)

	return rule, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.GetUserEmail(),
		rules.GetDirectoryUser(),
	}, nil
}

// Email returns a Criterion on a user's email address.
func Email(generator *Generator) Criterion {
	return emailCriterion{g: generator}
}

func init() {
	Register(Email)
}
