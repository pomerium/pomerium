package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var claimsBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		session_claims := object.get(session, "claims", {})
	`),
	ast.MustParseExpr(`
		user := get_user(session)
	`),
	ast.MustParseExpr(`
		user_claims := object.get(user, "claims", {})
	`),
	ast.MustParseExpr(`
		all_claims := object.union(session_claims, user_claims)
	`),
	ast.MustParseExpr(`
		values := object_get(all_claims, rule_path, [])
	`),
	ast.MustParseExpr(`
		rule_data == values[_]
	`),
}

type claimsCriterion struct {
	g *Generator
}

func (claimsCriterion) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnknown
}

func (claimsCriterion) Name() string {
	return "claim"
}

func (c claimsCriterion) GenerateRule(subPath string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("claims")
	r.Body = append(r.Body,
		ast.Assign.Expr(ast.VarTerm("rule_data"), ast.NewTerm(data.RegoValue())),
		ast.Assign.Expr(ast.VarTerm("rule_path"), ast.NewTerm(ast.MustInterfaceToValue(subPath))),
	)
	r.Body = append(r.Body, claimsBody...)

	return r, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.ObjectGet(),
	}, nil
}

// Claims returns a Criterion on allowed IDP claims.
func Claims(generator *Generator) Criterion {
	return claimsCriterion{g: generator}
}

func init() {
	Register(Claims)
}
