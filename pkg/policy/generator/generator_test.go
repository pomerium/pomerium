package generator

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func Test(t *testing.T) {
	g := New(WithCriterion(func(g *Generator) Criterion {
		return NewCriterionFunc([]string{"accept"}, func(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error) {
			rule = g.NewRule("accept")
			rule.Body = append(rule.Body, ast.MustParseExpr("1 == 1"))
			return rule, nil, nil
		})
	}))

	mod, err := g.Generate(&parser.Policy{
		Rules: []parser.Rule{
			{
				Action: parser.ActionAllow,
				And: []parser.Criterion{
					{Name: "accept"},
					{Name: "accept"},
					{Name: "accept"},
				},
				Or: []parser.Criterion{
					{Name: "accept"},
					{Name: "accept"},
					{Name: "accept"},
				},
				Not: []parser.Criterion{
					{Name: "accept"},
					{Name: "accept"},
					{Name: "accept"},
				},
				Nor: []parser.Criterion{
					{Name: "accept"},
					{Name: "accept"},
					{Name: "accept"},
				},
			},
			{
				Action: parser.ActionAllow,
				And: []parser.Criterion{
					{Name: "accept"},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, `package pomerium.policy

default allow = false

default deny = false

accept_0 {
	1 == 1
}

accept_1 {
	1 == 1
}

accept_2 {
	1 == 1
}

and_0 = v1 {
	v1 := accept_0
	v1
	v2 := accept_1
	v2
	v3 := accept_2
	v3
}

accept_3 {
	1 == 1
}

accept_4 {
	1 == 1
}

accept_5 {
	1 == 1
}

or_0 = v1 {
	v1 := accept_3
	v1
}

else = v2 {
	v2 := accept_4
	v2
}

else = v3 {
	v3 := accept_5
	v3
}

accept_6 {
	1 == 1
}

accept_7 {
	1 == 1
}

accept_8 {
	1 == 1
}

not_0 = v1 {
	v1 := accept_6
	not v1
	v2 := accept_7
	not v2
	v3 := accept_8
	not v3
}

accept_9 {
	1 == 1
}

accept_10 {
	1 == 1
}

accept_11 {
	1 == 1
}

nor_0 = v1 {
	v1 := accept_9
	not v1
}

else = v2 {
	v2 := accept_10
	not v2
}

else = v3 {
	v3 := accept_11
	not v3
}

accept_12 {
	1 == 1
}

and_1 = v1 {
	v1 := accept_12
	v1
}

allow = v1 {
	v1 := and_0
	v1
}

else = v2 {
	v2 := or_0
	v2
}

else = v3 {
	v3 := not_0
	v3
}

else = v4 {
	v4 := nor_0
	v4
}

else = v5 {
	v5 := and_1
	v5
}
`, string(format.MustAst(mod)))
}
