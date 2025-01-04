package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var userBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		user_id := session.user_id
	`),
}

type userCriterion struct {
	g *Generator
}

func (userCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (userCriterion) Name() string {
	return "user"
}

func (c userCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	body = append(body, userBody...)

	err := matchString(&body, ast.VarTerm("user_id"), data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonUserOK, ReasonUserUnauthorized,
		body)

	return rule, []*ast.Rule{
		rules.GetSession(),
	}, nil
}

// UserID returns a Criterion on a user's id.
func UserID(generator *Generator) Criterion {
	return userCriterion{g: generator}
}

func init() {
	Register(UserID)
}
