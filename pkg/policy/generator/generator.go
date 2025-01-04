// Package generator converts Pomerium Policy Language into Rego.
package generator

import (
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
)

// A Generator generates a rego script from a policy.
type Generator struct {
	ids      map[string]int
	criteria map[string]Criterion
}

// An Option configures the Generator.
type Option func(*Generator)

// WithCriterion adds a Criterion to the generator's known criteria.
func WithCriterion(criterionConstructor CriterionConstructor) Option {
	return func(g *Generator) {
		c := criterionConstructor(g)
		g.criteria[c.Name()] = c
	}
}

// New creates a new Generator.
func New(options ...Option) *Generator {
	g := &Generator{
		ids:      make(map[string]int),
		criteria: make(map[string]Criterion),
	}
	for _, o := range options {
		o(g)
	}
	return g
}

// GetCriterion gets a Criterion for the given name.
func (g *Generator) GetCriterion(name string) (Criterion, bool) {
	c, ok := g.criteria[name]
	return c, ok
}

// Generate generates the rego module from a policy.
func (g *Generator) Generate(policy *parser.Policy) (*ast.Module, error) {
	rs := ast.NewRuleSet()
	rs.Add(rules.MustParse(`default allow := [false, set()]`))
	rs.Add(rules.MustParse(`default deny := [false, set()]`))
	rs.Add(rules.InvertCriterionResult())
	rs.Add(rules.NormalizeCriterionResult())
	rs.Add(rules.ObjectUnion())
	rs.Add(rules.MergeWithAnd())
	rs.Add(rules.MergeWithOr())

	for _, action := range []parser.Action{parser.ActionAllow, parser.ActionDeny} {
		var terms []*ast.Term
		for _, policyRule := range policy.Rules {
			if policyRule.Action != action {
				continue
			}

			if len(policyRule.And) > 0 {
				subRule, err := g.generateAndRule(&rs, policyRule.And)
				if err != nil {
					return nil, err
				}
				terms = append(terms, ast.VarTerm(string(subRule.Head.Name)))
			}
			if len(policyRule.Or) > 0 {
				subRule, err := g.generateOrRule(&rs, policyRule.Or)
				if err != nil {
					return nil, err
				}
				terms = append(terms, ast.VarTerm(string(subRule.Head.Name)))
			}
			if len(policyRule.Not) > 0 {
				subRule, err := g.generateNotRule(&rs, policyRule.Not)
				if err != nil {
					return nil, err
				}
				terms = append(terms, ast.VarTerm(string(subRule.Head.Name)))
			}
			if len(policyRule.Nor) > 0 {
				subRule, err := g.generateNorRule(&rs, policyRule.Nor)
				if err != nil {
					return nil, err
				}
				terms = append(terms, ast.VarTerm(string(subRule.Head.Name)))
			}
		}
		if len(terms) > 0 {
			rule := &ast.Rule{
				Head: NewHead(ast.Var(action), ast.VarTerm("v")),
				Body: append(ast.Body{
					ast.Assign.Expr(ast.VarTerm("results"), ast.ArrayTerm(terms...)),
				}, orBody...),
			}
			rs.Add(rule)
		}
	}

	mod := &ast.Module{
		Package: &ast.Package{
			Path: ast.Ref{
				ast.StringTerm("policy.rego"),
				ast.StringTerm("pomerium"),
				ast.StringTerm("policy"),
			},
		},
		Imports: []*ast.Import{{
			Path: ast.RefTerm(ast.VarTerm("rego"), ast.StringTerm("v1")),
		}},
		Rules: rs,
	}

	// move functions to the end
	sort.SliceStable(mod.Rules, func(i, j int) bool {
		return len(mod.Rules[i].Head.Args) < len(mod.Rules[j].Head.Args)
	})

	i := 1
	ast.WalkRules(mod, func(r *ast.Rule) bool {
		r.SetLoc(ast.NewLocation([]byte(r.String()), "", i, 1))
		i++
		return false
	})

	return mod, nil
}

// NewRuleFromTemplate creates a new rule from a template rule.
func (g *Generator) NewRuleFromTemplate(name string, template *ast.Rule) *ast.Rule {
	id := g.ids[name]
	g.ids[name]++

	newRule := template.Copy()
	newRule.Head.Name = ast.Var(fmt.Sprintf("%s_%d", name, id))
	return newRule
}

// NewRule creates a new rule with a dynamically generated name.
func (g *Generator) NewRule(name string) *ast.Rule {
	id := g.ids[name]
	g.ids[name]++
	return &ast.Rule{
		Head: NewHead(ast.Var(fmt.Sprintf("%s_%d", name, id)), nil),
	}
}

// NewHead creates a new AST Head.
func NewHead(name ast.Var, value *ast.Term) *ast.Head {
	return &ast.Head{
		Name:   name,
		Value:  value,
		Assign: true,
	}
}
