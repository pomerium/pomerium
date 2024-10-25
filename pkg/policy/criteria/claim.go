package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var claimBody = ast.Body{
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
}

type claimCriterion struct {
	g *Generator
}

func (claimCriterion) DataType() CriterionDataType {
	return CriterionDataTypeStringListMatcher
}

func (claimCriterion) Name() string {
	return "claim"
}

func (c claimCriterion) GenerateRule(subPath string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	body = append(body, ast.Assign.Expr(ast.VarTerm("rule_path"), ast.NewTerm(ast.MustInterfaceToValue(subPath))))
	body = append(body, claimBody...)

	err := matchStringList(&body, ast.VarTerm("values"), data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonClaimOK, ReasonClaimUnauthorized,
		body)
	return rule, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.ObjectGet(),
	}, nil
}

// Claim returns a Criterion on allowed IDP claims.
func Claim(generator *Generator) Criterion {
	return claimCriterion{g: generator}
}

func init() {
	Register(Claim)
}
