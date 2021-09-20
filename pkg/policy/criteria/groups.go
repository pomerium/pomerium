package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

var groupsBody = ast.Body{
	ast.MustParseExpr(`
		session := get_session(input.session.id)
	`),
	ast.MustParseExpr(`
		directory_user := get_directory_user(session)
	`),
	ast.MustParseExpr(`
		group_ids := get_group_ids(session, directory_user)
	`),
	ast.MustParseExpr(`
		group_names := [directory_group.name |
			some i
			group_id := group_ids[i]
			directory_group := get_directory_group(group_id)
			directory_group != null
			directory_group.name != null]
	`),
	ast.MustParseExpr(`
		group_emails := [directory_group.email |
			some i
			group_id := group_ids[i]
			directory_group := get_directory_group(group_id)
			directory_group != null
			directory_group.email != null]
	`),
	ast.MustParseExpr(`
		groups = array.concat(group_ids, array.concat(group_names, group_emails))
	`),
}

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
	var body ast.Body
	body = append(body, groupsBody...)

	err := matchStringList(&body, ast.VarTerm("groups"), data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonGroupsOK, ReasonGroupsUnauthorized,
		body)

	return rule, []*ast.Rule{
		rules.GetSession(),
		rules.GetDirectoryUser(),
		rules.GetDirectoryGroup(),
		rules.GetGroupIDs(),
	}, nil
}

// Groups returns a Criterion on a user's group ids, names or emails.
func Groups(generator *Generator) Criterion {
	return groupsCriterion{g: generator}
}

func init() {
	Register(Groups)
}
