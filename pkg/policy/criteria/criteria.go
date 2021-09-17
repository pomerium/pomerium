// Package criteria contains all the pre-defined criteria as well as a registry to add new criteria.
package criteria

import (
	"sync"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/generator"
)

// re-exported types
type (
	// A Generator generates a rego script from a policy.
	Generator = generator.Generator
	// A Criterion generates rego rules based on data.
	Criterion = generator.Criterion
	// A CriterionConstructor is a function which returns a Criterion for a Generator.
	CriterionConstructor = generator.CriterionConstructor
	// The CriterionDataType indicates the expected type of data for the criterion.
	CriterionDataType = generator.CriterionDataType
)

var allCriteria struct {
	sync.Mutex
	a []CriterionConstructor
}

// All returns all the known criterion constructors.
func All() []CriterionConstructor {
	allCriteria.Lock()
	a := allCriteria.a
	allCriteria.Unlock()
	return a
}

// Register registers a criterion.
func Register(criterionConstructor CriterionConstructor) {
	allCriteria.Lock()
	a := make([]CriterionConstructor, 0, len(allCriteria.a)+1)
	a = append(a, allCriteria.a...)
	a = append(a, criterionConstructor)
	allCriteria.a = a
	allCriteria.Unlock()
}

const (
	// CriterionDataTypeStringListMatcher indicates the expected data type is a string list matcher.
	CriterionDataTypeStringListMatcher CriterionDataType = "string_list_matcher"
	// CriterionDataTypeStringMatcher indicates the expected data type is a string matcher.
	CriterionDataTypeStringMatcher CriterionDataType = "string_matcher"
)

// NewCriterionRule generates a new rule for a criterion.
func NewCriterionRule(
	g *generator.Generator,
	name string,
	passReason, failReason Reason,
	body ast.Body,
) *ast.Rule {
	r1 := g.NewRule(name)
	r1.Head.Value = NewCriterionTerm(true, passReason)
	r1.Body = body

	r2 := &ast.Rule{
		Head: &ast.Head{
			Value: NewCriterionTerm(false, failReason),
		},
		Body: ast.Body{
			ast.NewExpr(ast.BooleanTerm(true)),
		},
	}
	r1.Else = r2

	return r1
}

// NewCriterionSessionRule generates a new rule for a criterion which
// requires a session. If there is no session "user-unauthenticated"
// is returned.
func NewCriterionSessionRule(
	g *generator.Generator,
	name string,
	passReason, failReason Reason,
	body ast.Body,
) *ast.Rule {
	r1 := g.NewRule(name)
	r1.Head.Value = NewCriterionTerm(true, passReason)
	r1.Body = body

	r2 := &ast.Rule{
		Head: &ast.Head{
			Value: NewCriterionTerm(false, failReason),
		},
		Body: ast.Body{
			ast.MustParseExpr(`session := get_session(input.session.id)`),
			ast.MustParseExpr(`session.id != ""`),
		},
	}
	r1.Else = r2

	r3 := &ast.Rule{
		Head: &ast.Head{
			Value: NewCriterionTerm(false, ReasonUserUnauthenticated),
		},
		Body: ast.Body{
			ast.NewExpr(ast.BooleanTerm(true)),
		},
	}
	r2.Else = r3

	return r1
}

// NewCriterionTerm creates a new rego term for a criterion:
//
//    [true, {"reason"}]
//
func NewCriterionTerm(value bool, reasons ...Reason) *ast.Term {
	var terms []*ast.Term
	for _, r := range reasons {
		terms = append(terms, ast.StringTerm(string(r)))
	}
	return ast.ArrayTerm(
		ast.BooleanTerm(value),
		ast.SetTerm(terms...),
	)
}
