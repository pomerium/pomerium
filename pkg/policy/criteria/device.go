package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/generator"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/policy/rules"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

const (
	deviceOperatorApproved = "approved"
	deviceOperatorIs       = "is"
	deviceOperatorType     = "type"
)

var deviceOperatorLookup = map[string]struct{}{
	deviceOperatorApproved: {},
	deviceOperatorIs:       {},
	deviceOperatorType:     {},
}

type deviceCriterion struct {
	g *Generator
}

func (deviceCriterion) DataType() CriterionDataType {
	return generator.CriterionDataTypeUnknown
}

func (deviceCriterion) Name() string {
	return "device"
}

func (c deviceCriterion) GenerateRule(_ string, data parser.Value) (*ast.Rule, []*ast.Rule, error) {
	obj, ok := data.(parser.Object)
	if !ok {
		return nil, nil, fmt.Errorf("expected object for device criterion, got: %T", data)
	}

	for k := range obj {
		_, ok := deviceOperatorLookup[k]
		if !ok {
			return nil, nil, fmt.Errorf("unexpected field in device criterion: %s", k)
		}
	}

	var body ast.Body

	switch {
	case obj.Truthy(deviceOperatorApproved):
		// must be approved
		body = append(body, ast.Body{
			ast.MustParseExpr(`count([x|x:=device_enrollment.approved_by]) > 0`),
		}...)
	case obj.Falsy(deviceOperatorApproved):
		// must *not* be approved
		body = append(body, ast.Body{
			ast.MustParseExpr(`count([x|x:=device_enrollment.approved_by]) == 0`),
		}...)
	}

	if v, ok := obj[deviceOperatorIs]; ok {
		s, ok := v.(parser.String)
		if !ok {
			return nil, nil, fmt.Errorf("expected string for device criterion is operator, got %T", v)
		}
		body = append(body, ast.Body{
			ast.Assign.Expr(ast.VarTerm("is_expect"), ast.StringTerm(string(s))),
			ast.MustParseExpr(`is_expect == device_credential.id`),
		}...)
	}

	deviceType := webauthnutil.DefaultDeviceType
	if v, ok := obj[deviceOperatorType]; ok {
		s, ok := v.(parser.String)
		if !ok {
			return nil, nil, fmt.Errorf("expected string for device criterion type operator, got %T", v)
		}
		deviceType = string(s)
		body = append(body, ast.Body{
			ast.MustParseExpr(`device_credential.id != ""`),
		}...)
	}

	rule := NewCriterionDeviceRule(c.g, c.Name(),
		ReasonDeviceOK, ReasonDeviceUnauthorized,
		body, deviceType)
	return rule, []*ast.Rule{
		rules.GetDeviceCredential(),
		rules.GetDeviceEnrollment(),
		rules.GetSession(),
		rules.ObjectGet(),
	}, nil
}

// Device returns a Criterion based on the User's device state.
func Device(generator *Generator) Criterion {
	return deviceCriterion{g: generator}
}

func init() {
	Register(Device)
}
