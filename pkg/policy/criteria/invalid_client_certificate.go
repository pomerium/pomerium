package criteria

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var invalidClientCertificateBody = ast.Body{
	ast.MustParseExpr(`is_boolean(input.is_valid_client_certificate)`),
	ast.MustParseExpr(`not input.is_valid_client_certificate`),
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
	rule := NewCriterionRule(c.g, c.Name(),
		ReasonInvalidClientCertificate, ReasonValidClientCertificate,
		invalidClientCertificateBody)
	return rule, nil, nil
}

// InvalidClientCertificate returns a Criterion which returns true if the
// client certificate is invalid.
func InvalidClientCertificate(generator *Generator) Criterion {
	return invalidClientCertificateCriterion{g: generator}
}

func init() {
	Register(InvalidClientCertificate)
}
