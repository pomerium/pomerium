package generator

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func Test(t *testing.T) {
	g := New(WithCriterion(func(g *Generator) Criterion {
		return NewCriterionFunc(CriterionDataTypeUnused, "accept", func(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error) {
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
			{
				Action: parser.ActionDeny,
				Nor: []parser.Criterion{
					{Name: "accept"},
					{Name: "accept"},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, `package pomerium.policy

default allow = [false, set()]

default deny = [false, set()]

accept_0 {
	1 == 1
}

accept_1 {
	1 == 1
}

accept_2 {
	1 == 1
}

and_0 = v {
	results := [accept_0, accept_1, accept_2]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_and(normalized)
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

or_0 = v {
	results := [accept_3, accept_4, accept_5]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
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

not_0 = v {
	results := [accept_6, accept_7, accept_8]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	inverted := [invert_criterion_result(x) | x := results[i]]
	v := merge_with_and(inverted)
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

nor_0 = v {
	results := [accept_9, accept_10, accept_11]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	inverted := [invert_criterion_result(x) | x := results[i]]
	v := merge_with_or(inverted)
}

accept_12 {
	1 == 1
}

and_1 = v {
	results := [accept_12]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_and(normalized)
}

allow = v {
	results := [and_0, or_0, not_0, nor_0, and_1]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

accept_13 {
	1 == 1
}

accept_14 {
	1 == 1
}

nor_1 = v {
	results := [accept_13, accept_14]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	inverted := [invert_criterion_result(x) | x := results[i]]
	v := merge_with_or(inverted)
}

deny = v {
	results := [nor_1]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

invert_criterion_result(in) = out {
	in[0]
	out = array.concat([false], array.slice(in, 1, count(in)))
}

else = out {
	not in[0]
	out = array.concat([true], array.slice(in, 1, count(in)))
}

normalize_criterion_result(result) = v {
	is_boolean(result)
	v = [result, set()]
}

else = v {
	is_array(result)
	v = result
}

else = v {
	v = [false, set()]
}

object_union(xs) = merged {
	merged = {k: v |
		some k
		xs[_][k]
		vs := [xv | xv := xs[_][k]]
		v := vs[count(vs) - 1]
	}
}

merge_with_and(results) = [true, reasons, additional_data] {
	true_results := [x | x := results[i]; x[0]]
	count(true_results) == count(results)
	reasons := union({x | x := true_results[i][1]})
	additional_data := object_union({x | x := true_results[i][2]})
}

else = [false, reasons, additional_data] {
	false_results := [x | x := results[i]; not x[0]]
	reasons := union({x | x := false_results[i][1]})
	additional_data := object_union({x | x := false_results[i][2]})
}

merge_with_or(results) = [true, reasons, additional_data] {
	true_results := [x | x := results[i]; x[0]]
	count(true_results) > 0
	reasons := union({x | x := true_results[i][1]})
	additional_data := object_union({x | x := true_results[i][2]})
}

else = [false, reasons, additional_data] {
	false_results := [x | x := results[i]; not x[0]]
	reasons := union({x | x := false_results[i][1]})
	additional_data := object_union({x | x := false_results[i][2]})
}
`, string(format.MustAst(mod)))
}
