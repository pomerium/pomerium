// Package criteria contains all the pre-defined criteria as well as a registry to add new criteria.
package criteria

import (
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
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
	// CriterionDataTypeCertificateMatcher indicates the expected data type is
	// a certificate matcher.
	CriterionDataTypeCertificateMatcher CriterionDataType = "certificate_matcher"
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
		Head: generator.NewHead("", NewCriterionTerm(false, failReason)),
		Body: ast.Body{
			ast.NewExpr(ast.BooleanTerm(true)),
		},
	}
	r1.Else = r2

	return r1
}

// NewCriterionDeviceRule generates a new rule for a criterion which
// requires a device and session. If there is no device "device-unauthenticated"
// is returned. If there is no session "user-unauthenticated" is returned.
func NewCriterionDeviceRule(
	g *generator.Generator,
	name string,
	passReason, failReason Reason,
	body ast.Body,
	deviceType string,
) *ast.Rule {
	r1 := g.NewRule(name)

	additionalData := map[string]any{
		"device_type": deviceType,
	}

	sharedBody := ast.Body{
		ast.Assign.Expr(ast.VarTerm("device_type_id"), ast.StringTerm(deviceType)),
		ast.MustParseExpr(`session := get_session(input.session.id)`),
		ast.MustParseExpr(`device_credential := get_device_credential(session, device_type_id)`),
		ast.MustParseExpr(`device_enrollment := get_device_enrollment(device_credential)`),
	}

	// case 1: rule passes, session exists, device exists
	r1.Head.Value = NewCriterionTermWithAdditionalData(true, passReason, additionalData)
	r1.Body = append(sharedBody, body...)

	// case 2: rule fails, session exists, device exists
	r2 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTermWithAdditionalData(false, failReason, additionalData)),
		Body: append(sharedBody, ast.Body{
			ast.MustParseExpr(`session.id != ""`),
			ast.MustParseExpr(`device_credential.id != ""`),
			ast.MustParseExpr(`device_enrollment.id != ""`),
		}...),
	}
	r1.Else = r2

	// case 3: device not authenticated, session exists, device does not exist
	r3 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTermWithAdditionalData(false, ReasonDeviceUnauthenticated, additionalData)),
		Body: append(sharedBody, ast.Body{
			ast.MustParseExpr(`session.id != ""`),
		}...),
	}
	r2.Else = r3

	// case 4: user not authenticated, session does not exist
	r4 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTermWithAdditionalData(false, ReasonUserUnauthenticated, additionalData)),
		Body: ast.Body{
			ast.NewExpr(ast.BooleanTerm(true)),
		},
	}
	r3.Else = r4

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
		Head: generator.NewHead("", NewCriterionTerm(false, failReason)),
		Body: ast.Body{
			ast.MustParseExpr(`session := get_session(input.session.id)`),
			ast.MustParseExpr(`session.id != ""`),
		},
	}
	r1.Else = r2

	r3 := &ast.Rule{
		Head: generator.NewHead("", NewCriterionTerm(false, ReasonUserUnauthenticated)),
		Body: ast.Body{
			ast.NewExpr(ast.BooleanTerm(true)),
		},
	}
	r2.Else = r3

	return r1
}

// NewCriterionTerm creates a new rego term for a criterion:
//
//	[true, {"reason"}]
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

// NewCriterionTermWithAdditionalData creates a new rego term for a criterion with additional data:
//
//	[true, {"reason"}, {"key": "value"}]
func NewCriterionTermWithAdditionalData(value bool, reason Reason, additionalData map[string]any) *ast.Term {
	var kvs [][2]*ast.Term
	for k, v := range additionalData {
		kvs = append(kvs, [2]*ast.Term{
			ast.StringTerm(k),
			ast.NewTerm(ast.MustInterfaceToValue(v)),
		})
	}
	var terms []*ast.Term
	terms = append(terms, ast.StringTerm(string(reason)))
	return ast.ArrayTerm(
		ast.BooleanTerm(value),
		ast.SetTerm(terms...),
		ast.ObjectTerm(kvs...),
	)
}
