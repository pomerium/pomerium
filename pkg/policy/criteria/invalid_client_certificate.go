package criteria

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var validClientCertificateBody = ast.Body{
	ast.MustParseExpr(`is_boolean(input.is_valid_client_certificate)`),
	ast.MustParseExpr(`input.is_valid_client_certificate`),
}

var noClientCertificateBody = ast.Body{
	ast.MustParseExpr(`is_boolean(input.http.client_certificate.presented)`),
	ast.MustParseExpr(`not input.http.client_certificate.presented`),
}

type invalidClientCertificateCriterion struct {
	g *Generator
}

func (invalidClientCertificateCriterion) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnused
}

func (invalidClientCertificateCriterion) Name() string {
	return "invalid_client_certificate"
}

func (c invalidClientCertificateCriterion) GenerateRule(_ string, _ parser.Value) (*ast.Rule, []*ast.Rule, error) {
	r1 := c.g.NewRule(c.Name())
	r1.Head.Value = NewCriterionTerm(false, ReasonValidClientCertificate)
	r1.Body = validClientCertificateBody

	r2 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(true, ReasonClientCertificateRequired)),
		Body: noClientCertificateBody,
	}
	r1.Else = r2

	r3 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(true, ReasonInvalidClientCertificate)),
	}
	r2.Else = r3

	return r1, nil, nil
}

// InvalidClientCertificate returns a Criterion which returns true if the
// client certificate is invalid.
func InvalidClientCertificate(generator *Generator) Criterion {
	return invalidClientCertificateCriterion{g: generator}
}

func init() {
	Register(InvalidClientCertificate)
}
