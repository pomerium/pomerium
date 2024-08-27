package testenv

import (
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// PolicyRoute is a [Route] implementation suitable for most common use cases
// that can be used in implementations of [Upstream].
type PolicyRoute struct {
	DefaultAttach
	from  values.Value[string]
	to    values.List[string]
	edits []func(*config.Policy)
}

// Modify implements Route.
func (b *PolicyRoute) Modify(cfg *config.Config) {
	to := make(config.WeightedURLs, 0, len(b.to))
	for _, u := range b.to {
		u, err := url.Parse(u.Value())
		if err != nil {
			panic(err)
		}
		to = append(to, config.WeightedURL{URL: *u})
	}
	p := config.Policy{
		From: b.from.Value(),
		To:   to,
	}
	for _, edit := range b.edits {
		edit(&p)
	}
	cfg.Options.Policies = append(cfg.Options.Policies, p)
}

// From implements Route.
func (b *PolicyRoute) From(fromUrl values.Value[string]) Route {
	b.from = fromUrl
	return b
}

// To implements Route.
func (b *PolicyRoute) To(toUrl values.Value[string]) Route {
	b.to = append(b.to, toUrl)
	return b
}

// To implements Route.
func (b *PolicyRoute) Policy(edit func(*config.Policy)) Route {
	b.edits = append(b.edits, edit)
	return b
}

// PPL implements Route.
func (b *PolicyRoute) PPL(ppl string) Route {
	pplPolicy, err := parser.ParseYAML(strings.NewReader(ppl))
	if err != nil {
		panic(err)
	}
	b.edits = append(b.edits, func(p *config.Policy) {
		p.Policy = &config.PPLPolicy{
			Policy: pplPolicy,
		}
	})
	return b
}

// To implements Route.
func (b *PolicyRoute) URL() values.Value[string] {
	return b.from
}
