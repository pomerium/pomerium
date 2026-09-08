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

type sshAccessRequestApprovedCriterion struct {
	g *Generator
}

func (sshAccessRequestApprovedCriterion) DataType() generator.CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (sshAccessRequestApprovedCriterion) Name() string {
	return "ssh_access_request_approved"
}

func (c sshAccessRequestApprovedCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r1 := c.g.NewRule(c.Name())
	r1.Head.Value = NewCriterionTerm(true, ReasonSSHAccessRequestOK)
	r1.Body = accessRequestApprovedBody
	r1.Else = &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(false, ReasonSSHAccessRequestRequired)),
	}
	return r1, nil, nil
}

func SSHAccessRequestApprovedCriterion(generator *Generator) Criterion {
	return sshAccessRequestApprovedCriterion{g: generator}
}

func init() {
	Register(SSHAccessRequestApprovedCriterion)
}
