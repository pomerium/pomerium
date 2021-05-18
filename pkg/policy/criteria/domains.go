package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var domainsBody = ast.Body{
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

type domainsCriterion struct {
	g *Generator
}

func (domainsCriterion) Names() []string {
	return []string{"domain", "domains"}
}

func (c domainsCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("domains")
	r.Body = append(r.Body, ast.Assign.Expr(ast.VarTerm("rule_data"), ast.NewTerm(data.RegoValue())))
	r.Body = append(r.Body, domainsBody...)

	switch data.(type) {
	case parser.String:
		r.Body = append(r.Body, ast.MustParseExpr(`domain == rule_data`))
	default:
		return nil, nil, fmt.Errorf("unsupported value type: %T", data)
	}

	return r, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.GetUserEmail(),
	}, nil
}

// Domains returns a Criterion on a user's email address domain.
func Domains(generator *Generator) Criterion {
	return domainsCriterion{g: generator}
}

func init() {
	Register(Domains)
}
