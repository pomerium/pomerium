package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

type groupsCriterion struct {
	g *Generator
}

func (groupsCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringListMatcher
}

func (groupsCriterion) Name() string {
	return "groups"
}

func (c groupsCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	body := ast.Body{
		ast.Assign.Expr(ast.VarTerm("record_type"), ast.StringTerm(directory.UserRecordType)),

		ast.MustParseExpr(`session := get_session(input.session.id)`),
		ast.MustParseExpr(`directory_user := get_databroker_record(record_type, session.user_id)`),
		ast.MustParseExpr(`group_ids := object.get(directory_user, "group_ids", [])`),
	}

	err := matchStringList(&body, ast.VarTerm("group_ids"), data)
	if err != nil {
		return nil, nil, err
	}

	r := NewCriterionSessionRule(c.g, c.Name(),
		ReasonGroupsOK, ReasonGroupsUnauthorized,
		body)
	return r, []*ast.Rule{
		rules.GetSession(),
	}, nil
}

// Groups returns a Criterion on a user's group ids
func Groups(generator *Generator) Criterion {
	return groupsCriterion{g: generator}
}

func init() {
	Register(Groups)
}
