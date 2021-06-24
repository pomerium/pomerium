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

	terms, err := g.generateCriterionRules(dst, policyCriteria)
	if err != nil {
		return nil, err
	}

	g.fillViaSetComprehension(rule, terms, true, true)
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

	g.fillViaOr(rule, terms)
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

	g.fillViaSetComprehension(rule, terms, false, true)
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

func (g *Generator) fillViaAnd(rule *ast.Rule, terms []*ast.Term) {
	currentRule := rule
	currentRule.Head.Value = ast.VarTerm("v1")
	for i, term := range terms {
		nm := fmt.Sprintf("v%d", i+1)
		currentRule.Body = append(currentRule.Body, ast.Assign.Expr(ast.VarTerm(nm), term))
		expr := ast.NewExpr(ast.VarTerm(nm))
		currentRule.Body = append(currentRule.Body, expr)
	}
}

func (g *Generator) fillViaOr(rule *ast.Rule, terms []*ast.Term) {
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
		currentRule.Body = append(currentRule.Body, expr)
	}
}

func (g *Generator) fillViaSetComprehension(rule *ast.Rule, terms []*ast.Term, useIntersection, negated bool) {
	sets := make([]*ast.Term, len(terms))
	for i, term := range terms {
		e := ast.NewExpr(term)
		e.Negated = negated
		sets[i] = ast.SetComprehensionTerm(ast.NumberTerm("1"), ast.NewBody(e))
	}

	var builtIn *ast.Builtin
	if useIntersection {
		builtIn = ast.And
	} else {
		builtIn = ast.Or
	}
	rule.Head.Value = ast.VarTerm("v")
	rule.Body = ast.NewBody(
		ast.Assign.Expr(
			ast.VarTerm("v"),
			ast.Equal.Call(
				ast.Count.Call(
					mergeTerms(builtIn, sets...),
				),
				ast.NumberTerm("1"),
			),
		),
	)
}

func mergeTerms(builtIn *ast.Builtin, terms ...*ast.Term) *ast.Term {
	// mergeTerms(AND, A, B, C, D) => AND(AND(A, B), AND(C, D))
	switch len(terms) {
	case 0:
		return ast.NullTerm()
	case 1:
		return terms[0]
	default:
		return builtIn.Call(
			mergeTerms(builtIn, terms[:len(terms)/2]...),
			mergeTerms(builtIn, terms[len(terms)/2:]...),
		)
	}
}
