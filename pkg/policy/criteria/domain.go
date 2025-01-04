package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var domainBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		user := get_user(session)
	`),
	ast.MustParseExpr(`
		domain := split(get_user_email(session, user), "@")[1]
	`),
}

type domainCriterion struct {
	g *Generator
}

func (domainCriterion) DataType() CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (domainCriterion) Name() string {
	return "domain"
}

func (c domainCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	body = append(body, domainBody...)

	err := matchString(&body, ast.VarTerm("domain"), data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonDomainOK, ReasonDomainUnauthorized,
		body)

	return rule, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.GetUserEmail(),
	}, nil
}

// Domain returns a Criterion on a user's email address domain.
func Domain(generator *Generator) Criterion {
	return domainCriterion{g: generator}
}

func init() {
	Register(Domain)
}
