// Package criteria contains all the pre-defined criteria as well as a registry to add new criteria.
package criteria

import (
	"sync"

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
