package generator

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// A Criterion generates rego rules based on data.
type Criterion interface {
	DataType() CriterionDataType
	Name() string
	GenerateRule(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error)
}

// A CriterionConstructor is a function which returns a Criterion for a Generator.
type CriterionConstructor func(*Generator) Criterion

// A criterionFunc is a criterion implemented as a function and a list of names.
type criterionFunc struct {
	dataType     CriterionDataType
	name         string
	generateRule func(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error)
}

// DataType returns the criterion data type.
func (c criterionFunc) DataType() CriterionDataType {
	return c.dataType
}

// Name returns the name of the criterion.
func (c criterionFunc) Name() string {
	return c.name
}

// GenerateRule calls the underlying generateRule function.
func (c criterionFunc) GenerateRule(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error) {
	return c.generateRule(subPath, data)
}

// NewCriterionFunc creates a new Criterion from a function.
func NewCriterionFunc(
	dataType CriterionDataType,
	name string,
	f func(subPath string, data parser.Value) (rule *ast.Rule, additionalRules []*ast.Rule, err error),
) Criterion {
	return criterionFunc{
		dataType:     dataType,
		name:         name,
		generateRule: f,
	}
}

// A CriterionDataType describes the expected format of the data to be sent to the criterion.
type CriterionDataType string

const (
	// CriterionDataTypeUnknown indicates that the type of data is unknown.
	CriterionDataTypeUnknown CriterionDataType = ""

	// CriterionDataTypeUnused indicates that the data is unused.
	CriterionDataTypeUnused CriterionDataType = "unused"
)
