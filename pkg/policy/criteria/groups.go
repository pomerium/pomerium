package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

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
	ast.MustParseExpr(`
		some group
	`),
	ast.MustParseExpr(`
		group = groups[_]
	`),
}

type groupsCriterion struct {
	g *Generator
}

func (groupsCriterion) Names() []string {
	return []string{"group", "groups"}
}

func (c groupsCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r := c.g.NewRule("groups")
	r.Body = append(r.Body, ast.Assign.Expr(ast.VarTerm("rule_data"), ast.NewTerm(data.RegoValue())))
	r.Body = append(r.Body, groupsBody...)

	switch data.(type) {
	case parser.String:
		r.Body = append(r.Body, ast.MustParseExpr(`group == rule_data`))
	default:
		return nil, nil, fmt.Errorf("unsupported value type: %T", data)
	}

	return r, []*ast.Rule{
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
