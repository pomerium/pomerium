package generator

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func (g *Generator) generateAndRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("and")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	expressions, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaAnd(rule, false, expressions)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateNotRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("not")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	// NOT => (NOT A) AND (NOT B)

	terms, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaAnd(rule, true, terms)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateOrRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("or")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	terms, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaOr(rule, false, terms)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateNorRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("nor")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	// NOR => (NOT A) OR (NOT B)

	terms, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaOr(rule, true, terms)
	dst.Add(rule)

	return rule, nil
}

func (g *Generator) generateCriterionRules(dst *ast.RuleSet, policyCriteria []parser.Criterion) ([]*ast.Term, error) {
	var terms []*ast.Term
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

		terms = append(terms, ast.VarTerm(string(mainRule.Head.Name)))
	}
	return terms, nil
}

func (g *Generator) fillViaAnd(rule *ast.Rule, negated bool, terms []*ast.Term) {
	currentRule := rule
	currentRule.Head.Value = ast.VarTerm("v1")
	for i, term := range terms {
		nm := fmt.Sprintf("v%d", i+1)
		currentRule.Body = append(currentRule.Body, ast.Assign.Expr(ast.VarTerm(nm), term))
		expr := ast.NewExpr(ast.VarTerm(nm))
		if negated {
			expr.Negated = true
		}
		currentRule.Body = append(currentRule.Body, expr)
	}
}

func (g *Generator) fillViaOr(rule *ast.Rule, negated bool, terms []*ast.Term) {
	currentRule := rule
	for i, term := range terms {
		if i > 0 {
			currentRule.Else = &ast.Rule{Head: &ast.Head{}}
			currentRule = currentRule.Else
		}
		nm := fmt.Sprintf("v%d", i+1)
		currentRule.Head.Value = ast.VarTerm(nm)

		currentRule.Body = append(currentRule.Body, ast.Assign.Expr(ast.VarTerm(nm), term))
		expr := ast.NewExpr(ast.VarTerm(nm))
		if negated {
			expr.Negated = true
		}
		currentRule.Body = append(currentRule.Body, expr)
	}
}
