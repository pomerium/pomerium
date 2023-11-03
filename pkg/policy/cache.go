package policy

import (
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/open-policy-agent/opa/format"

	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type cachingGenerator struct {
	cache *lru.Cache[uint64, string]
}

func newCachingGenerator() *cachingGenerator {
	c, err := lru.New[uint64, string](10_000)
	if err != nil {
		panic(err)
	}
	return &cachingGenerator{
		cache: c,
	}
}

func (c *cachingGenerator) GenerateRegoFromPolicy(p *parser.Policy) (string, error) {
	hash := p.Hash()
	if rego, ok := c.cache.Get(hash); ok {
		return rego, nil
	}

	var gOpts []generator.Option
	for _, ctor := range criteria.All() {
		gOpts = append(gOpts, generator.WithCriterion(ctor))
	}
	g := generator.New(gOpts...)

	mod, err := g.Generate(p)
	if err != nil {
		return "", err
	}

	bs, err := format.Ast(mod)
	if err != nil {
		return "", err
	}

	rego := string(bs)
	c.cache.Add(hash, rego)
	return rego, nil
}

var globalCachingGenerator = newCachingGenerator()
