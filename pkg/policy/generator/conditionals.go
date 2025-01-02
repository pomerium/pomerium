package generator

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

var (
	andBody = ast.Body{
		ast.MustParseExpr(`normalized := [normalize_criterion_result(x)|x:=results[i]]`),
		ast.MustParseExpr(`v := merge_with_and(normalized)`),
	}
	notBody = ast.Body{
		ast.MustParseExpr(`normalized := [normalize_criterion_result(x)|x:=results[i]]`),
		ast.MustParseExpr(`inverted := [invert_criterion_result(x)|x:=results[i]]`),
		ast.MustParseExpr(`v := merge_with_and(inverted)`),
	}
	orBody = ast.Body{
		ast.MustParseExpr(`normalized := [normalize_criterion_result(x)|x:=results[i]]`),
		ast.MustParseExpr(`v := merge_with_or(normalized)`),
	}
	norBody = ast.Body{
		ast.MustParseExpr(`normalized := [normalize_criterion_result(x)|x:=results[i]]`),
		ast.MustParseExpr(`inverted := [invert_criterion_result(x)|x:=results[i]]`),
		ast.MustParseExpr(`v := merge_with_or(inverted)`),
	}
)

func (g *Generator) generateAndRule(dst *ast.RuleSet, policyCriteria []parser.Criterion) (*ast.Rule, error) {
	rule := g.NewRule("and")

	if len(policyCriteria) == 0 {
		return rule, nil
	}

	terms, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	rule.Head.Value = ast.VarTerm("v")
	rule.Body = append(ast.Body{
		ast.Assign.Expr(ast.VarTerm("results"), ast.ArrayTerm(terms...)),
	}, andBody...)

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

	rule.Head.Value = ast.VarTerm("v")
	rule.Body = append(ast.Body{
		ast.Assign.Expr(ast.VarTerm("results"), ast.ArrayTerm(terms...)),
	}, notBody...)

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

	rule.Head.Value = ast.VarTerm("v")
	rule.Body = append(ast.Body{
		ast.Assign.Expr(ast.VarTerm("results"), ast.ArrayTerm(terms...)),
	}, orBody...)

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

	rule.Head.Value = ast.VarTerm("v")
	rule.Body = append(ast.Body{
		ast.Assign.Expr(ast.VarTerm("results"), ast.ArrayTerm(terms...)),
	}, norBody...)

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
