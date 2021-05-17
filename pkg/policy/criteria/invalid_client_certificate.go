package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var invalidClientCertificateBody = ast.Body{
	ast.MustParseExpr(`reason = [495, "invalid client certificate"]`),
	ast.MustParseExpr(`is_boolean(input.is_valid_client_certificate)`),
	ast.MustParseExpr(`not input.is_valid_client_certificate`),
}

type invalidClientCertificateCriterion struct {
	g *Generator
}

func (invalidClientCertificateCriterion) Names() []string {
	return []string{"invalid_client_certificate"}
}

func (c invalidClientCertificateCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	rule := c.g.NewRule("invalid_client_certificate")
	rule.Head.Value = ast.VarTerm("reason")
	rule.Body = invalidClientCertificateBody
	return rule, nil, nil
}

// InvalidClientCertificate returns a Criterion which returns true if the client certificate is valid.
func InvalidClientCertificate(generator *Generator) Criterion {
	return invalidClientCertificateCriterion{g: generator}
}

func init() {
	Register(InvalidClientCertificate)
}
