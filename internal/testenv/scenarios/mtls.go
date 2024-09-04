package scenarios

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"text/template"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func DownstreamMTLS(mode config.MTLSEnforcement) testenv.Modifier {
	return testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
		env := testenv.EnvFromContext(ctx)
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: env.CACert().Leaf.Raw,
		}
		cfg.Options.DownstreamMTLS = config.DownstreamMTLSSettings{
			CA:          base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&block)),
			Enforcement: mode,
		}
	})
}

type PolicyTemplate struct {
	From string
	To   string
	PPL  string

	// Add more fields as needed (be sure to update newPolicyFromTemplate)
}

func TemplateRoutes(n int, tmpl PolicyTemplate) testenv.Modifier {
	return testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
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
