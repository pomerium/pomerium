package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var accessRequestApprovedBody = ast.Body{
	ast.MustParseExpr(`is_boolean(input.ssh.access_request_approved)`),
	ast.MustParseExpr(`input.ssh.access_request_approved`),
}

type sshAccessRequestNotApprovedCriterion struct {
	g *Generator
}

func (sshAccessRequestNotApprovedCriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (sshAccessRequestNotApprovedCriterion) Name() string {
	return "ssh_access_request_not_approved"
}

func (c sshAccessRequestNotApprovedCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r1 := c.g.NewRule(c.Name())
	r1.Head.Value = NewCriterionTerm(false, ReasonSSHAccessRequestOK)
	r1.Body = accessRequestApprovedBody
	r1.Else = &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(true, ReasonSSHAccessRequestRequired)),
	}
	return r1, nil, nil
}

func SSHAccessRequestNotApprovedCriterion(generator *Generator) Criterion {
	return sshAccessRequestNotApprovedCriterion{g: generator}
}

func init() {
	Register(SSHAccessRequestNotApprovedCriterion)
}
