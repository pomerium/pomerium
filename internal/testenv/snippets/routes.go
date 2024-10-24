package snippets

import (
	"bytes"
	"context"
	"strings"
	"text/template"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var SimplePolicyTemplate = PolicyTemplate{
	From: "https://from-{{.Idx}}.localhost",
	To:   "https://to-{{.Idx}}.localhost",
	PPL:  `{"allow":{"and":["email":{"is":"user-{{.Idx}}@example.com"}]}}`,
}

type PolicyTemplate struct {
	From string
	To   string
	PPL  string

	// Add more fields as needed (be sure to update newPolicyFromTemplate)
}

func TemplateRoutes(n int, tmpl PolicyTemplate) testenv.Modifier {
	return testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		for i := range n {
			cfg.Options.Policies = append(cfg.Options.Policies, newPolicyFromTemplate(i, tmpl))
		}
	})
}

func newPolicyFromTemplate(i int, pt PolicyTemplate) config.Policy {
	eval := func(in string) string {
		t := template.New("policy")
		tmpl, err := t.Parse(in)
		if err != nil {
			panic(err)
		}
		var out bytes.Buffer
		if err := tmpl.Execute(&out, struct{ Idx int }{i}); err != nil {
			panic(err)
		}
		return out.String()
	}

	pplPolicy, err := parser.ParseYAML(strings.NewReader(eval(pt.PPL)))
	if err != nil {
		panic(err)
	}

	to, err := config.ParseWeightedUrls(eval(pt.To))
	if err != nil {
		panic(err)
	}
	return config.Policy{
		From:   eval(pt.From),
		To:     to,
		Policy: &config.PPLPolicy{Policy: pplPolicy},
	}
}
