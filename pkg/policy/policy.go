// Package policy contains an implementation of the Pomerium Policy Language.
package policy

import (
	"io"

	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// re-exported types
type (
	// A Criterion generates rego rules based on data.
	Criterion = generator.Criterion
	// A CriterionConstructor is a function which returns a Criterion for a Generator.
	CriterionConstructor = generator.CriterionConstructor
)

// GenerateRegoFromReader generates a rego script from raw Pomerium Policy Language.
func GenerateRegoFromReader(r io.Reader) (string, error) {
	ppl, err := parser.ParseYAML(r)
	if err != nil {
		return "", err
	}
	return GenerateRegoFromPolicy(ppl)
}

// GenerateRegoFromPolicy generates a rego script from a Pomerium Policy Language policy.
func GenerateRegoFromPolicy(p *parser.Policy) (string, error) {
	return globalCachingGenerator.GenerateRegoFromPolicy(p)
}
