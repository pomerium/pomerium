// Package policy contains an implementation of the Pomerium Policy Language.
package policy

import (
	"io"

	"github.com/open-policy-agent/opa/format"

	"github.com/pomerium/pomerium/pkg/policy/criteria"
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

// GenerateRegoFromPPL generates a rego script from raw Pomerium Policy Language.
func GenerateRegoFromPPL(r io.Reader) (string, error) {
	p := parser.New()
	var gOpts []generator.Option
	for _, ctor := range criteria.All() {
		gOpts = append(gOpts, generator.WithCriterion(ctor))
	}
	g := generator.New(gOpts...)

	ppl, err := p.ParseYAML(r)
	if err != nil {
		return "", err
	}

	mod, err := g.Generate(ppl)
	if err != nil {
		return "", err
	}

	bs, err := format.Ast(mod)
	if err != nil {
		return "", err
	}

	return string(bs), err
}
