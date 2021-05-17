package generator

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type conditionalGenerator func(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error)

func (g *Generator) generateAndRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("and")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	expressions, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaAnd(rule, expressions)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateNotRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("not")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	// NOT => (NOT A) AND (NOT B)

	expressions, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}
	for _, expr := range expressions {
		expr.Negated = true
	}

	g.fillViaAnd(rule, expressions)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateOrRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("or")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	expressions, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaOr(rule, expressions)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateNorRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("nor")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	// NOR => (NOT A) OR (NOT B)

	expressions, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}
	for _, expr := range expressions {
		expr.Negated = true
	}

	g.fillViaOr(rule, expressions)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateCriterionRules(dst *ast.RuleSet, policyCriteria []parser.Criterion) ([]*ast.Expr, error) {
	var expressions []*ast.Expr
	for _, policyCriterion := range policyCriteria {
		criterion, ok := g.criteria[policyCriterion.Name]
		if !ok {
			return nil, fmt.Errorf("unknown policy criterion: %s", policyCriterion.Name)
		}
		mainRule, additionalRules, err := criterion.GenerateRule(policyCriterion.SubPath, policyCriterion.Data)
		if err != nil {
			return nil, fmt.Errorf("error generating criterion rules: %w", err)
		}
		*dst = dst.Merge(additionalRules)
		dst.Add(mainRule)

		expr := ast.NewExpr(ast.VarTerm(string(mainRule.Head.Name)))
		expressions = append(expressions, expr)
	}
	return expressions, nil
}

func (g *Generator) fillViaAnd(rule *ast.Rule, expressions []*ast.Expr) {
	for _, expr := range expressions {
		rule.Body = append(rule.Body, expr)
	}
}

func (g *Generator) fillViaOr(rule *ast.Rule, expressions []*ast.Expr) {
	currentRule := rule
	for i, expr := range expressions {
		if i > 0 {
			currentRule.Else = &ast.Rule{
				Head: &ast.Head{},
			}
			currentRule = currentRule.Else
		}
		currentRule.Body = ast.Body{expr}
	}
}
