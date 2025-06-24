package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

type sshUsernameCriterion struct {
	g *Generator
}

func (sshUsernameCriterion) DataType() generator.CriterionDataType {
	return CriterionDataTypeStringMatcher
}

func (sshUsernameCriterion) Name() string {
	return "ssh_username"
}

func (c sshUsernameCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body

	err := matchString(&body, ast.VarTerm("input.ssh.username"), data)
	if err != nil {
		return nil, nil, err
	}

	rule := NewCriterionRule(c.g, c.Name(),
		ReasonSSHUsernameOK, ReasonSSHUsernameUnauthorized,
		body)

	return rule, nil, nil
}

func SSHUsername(generator *Generator) Criterion {
	return sshUsernameCriterion{g: generator}
}

type sshUsernameFromEmailCriterion struct {
	g *Generator
}

func (sshUsernameFromEmailCriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (sshUsernameFromEmailCriterion) Name() string {
	return "ssh_username_from_email"
}

func (c sshUsernameFromEmailCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	var body ast.Body
	body = append(body, emailBody...)
	body = append(body, ast.MustParseExpr(`username := split(email, "@")[0]`))
	body = append(body, ast.Equal.Expr(ast.VarTerm("input.ssh.username"), ast.VarTerm("username")))

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonSSHUsernameOK, ReasonSSHUsernameUnauthorized,
		body)

	return rule, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.GetUserEmail(),
		rules.GetDirectoryUser(),
	}, nil
}

func SSHUsernameFromEmail(generator *Generator) Criterion {
	return sshUsernameFromEmailCriterion{g: generator}
}

type sshUsernameFromClaimCriterion struct {
	g *Generator
}

func (sshUsernameFromClaimCriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnknown
}

func (sshUsernameFromClaimCriterion) Name() string {
	return "ssh_username_from_claim"
}

func (c sshUsernameFromClaimCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	claimName, ok := data.(parser.String)
	if !ok {
		return nil, nil, fmt.Errorf("expected string value, got: %T", data)
	}

	var body ast.Body
	body = append(body, ast.Assign.Expr(ast.VarTerm("rule_path"), ast.NewTerm(ast.String(claimName))))
	body = append(body, claimBody...)
	body = append(body, ast.Member.Expr(ast.VarTerm("input.ssh.username"), ast.VarTerm("values")))

	rule := NewCriterionSessionRule(c.g, c.Name(),
		ReasonSSHUsernameOK, ReasonSSHUsernameUnauthorized,
		body)

	return rule, []*ast.Rule{
		rules.GetSession(),
		rules.GetUser(),
		rules.ObjectGet(),
	}, nil
}

func SSHUsernameFromClaim(generator *Generator) Criterion {
	return sshUsernameFromClaimCriterion{g: generator}
}

func init() {
	Register(SSHUsername)
	Register(SSHUsernameFromEmail)
	Register(SSHUsernameFromClaim)
}
