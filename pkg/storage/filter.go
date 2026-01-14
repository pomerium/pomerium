package storage

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	ErrLogicalOperatorNotSupported = status.Error(codes.Unimplemented, "logical operator not supported")
	ErrOperatorNotSupported        = status.Errorf(codes.Unimplemented, "operator not supported")
)

// A FilterExpression describes an AST for record stream filters.
type FilterExpression interface {
	isFilterExpression()
}

// FilterExpressionFromStruct creates a FilterExpression from a protobuf struct.
func FilterExpressionFromStruct(s *structpb.Struct) (FilterExpression, error) {
	if s == nil {
		return nil, nil
	}
	return filterExpressionFromStruct(nil, s)
}

func filterExpressionFromValue(path []string, v *structpb.Value) (FilterExpression, error) {
	switch vv := v.GetKind().(type) {
	case *structpb.Value_ListValue:
		var or OrFilterExpression
		for _, vvv := range vv.ListValue.Values {
			e, err := filterExpressionFromValue(path, vvv)
			if err != nil {
				return nil, err
			}
			or = append(or, e)
		}
		return or, nil
	case *structpb.Value_StructValue:
		return filterExpressionFromStruct(path, vv.StructValue)
	}
	return SimpleFilterExpression{
		Fields:   path,
		Operator: FilterExpressionOperatorEquals,
		Value:    v,
	}, nil
}

func filterExpressionFromStruct(path []string, s *structpb.Struct) (FilterExpression, error) {
	var and AndFilterExpression
	var fs []string
	for f := range s.GetFields() {
		fs = append(fs, f)
	}
	sort.Strings(fs)

	for _, f := range fs {
		v := s.GetFields()[f]
		switch f {
		case "$and":
			expr, err := filterExpressionFromValue(path, v)
			if err != nil {
				return nil, err
			}
			or, ok := expr.(OrFilterExpression)
			if !ok {
				return nil, fmt.Errorf("$and must be an array")
			}
			if len(or) == 1 {
				and = append(and, or[0])
			} else {
				and = append(and, AndFilterExpression(or))
			}
		case "$not":
			expr, err := filterExpressionFromValue(path, v)
			if err != nil {
				return nil, err
			}
			and = append(and, NotFilterExpression{expr})
		case "$or":
			expr, err := filterExpressionFromValue(path, v)
			if err != nil {
				return nil, err
			}
			or, ok := expr.(OrFilterExpression)
			if !ok {
				return nil, fmt.Errorf("$or must be an array")
			}
			if len(or) == 1 {
				and = append(and, or[0])
			} else {
				and = append(and, or)
			}
		default:
			if op, ok := FilterExpressionOperatorFromField(f); ok {
				and = append(and, SimpleFilterExpression{
					Fields:   path,
					Operator: op,
					Value:    v,
				})
			} else {
				expr, err := filterExpressionFromValue(append(path, f), v)
				if err != nil {
					return nil, err
				}
				and = append(and, expr)
			}
		}
	}

	if len(and) == 1 {
		return and[0], nil
	}
	return and, nil
}

// An OrFilterExpression represents a logical-or comparison operator.
type OrFilterExpression []FilterExpression

func (OrFilterExpression) isFilterExpression() {}

// An AndFilterExpression represents a logical-and comparison operator.
type AndFilterExpression []FilterExpression

func (AndFilterExpression) isFilterExpression() {}

// A NotFilterExpression represents a not comparison operator.
type NotFilterExpression struct {
	FilterExpression FilterExpression
}

func (NotFilterExpression) isFilterExpression() {}

// A SimpleFilterExpression represents a field comparison operator.
type SimpleFilterExpression struct {
	Fields   []string
	Operator FilterExpressionOperator
	Value    *structpb.Value
}

func (SimpleFilterExpression) isFilterExpression() {}

// MustEqualsFilterExpression creates a simple equals filter expression from a path and value.
// It panics if the value can't be converted into a struct value.
func MustEqualsFilterExpression(path string, value any) FilterExpression {
	v, err := structpb.NewValue(value)
	if err != nil {
		panic(err)
	}
	return SimpleFilterExpression{Fields: strings.Split(path, "."), Operator: FilterExpressionOperatorEquals, Value: v}
}

// ValueAsString returns the value as a string.
func (expr SimpleFilterExpression) ValueAsString() string {
	switch v := expr.Value.Kind.(type) {
	case *structpb.Value_BoolValue:
		return fmt.Sprint(v.BoolValue)
	case *structpb.Value_ListValue:
		return v.ListValue.String()
	case *structpb.Value_NullValue:
		return ""
	case *structpb.Value_NumberValue:
		return fmt.Sprint(v.NumberValue)
	case *structpb.Value_StringValue:
		return v.StringValue
	case *structpb.Value_StructValue:
		return v.StructValue.String()
	}
	return ""
}

// A FilterExpressionOperator is an operator used in a filter expression.
type FilterExpressionOperator string

// filter expression operators
const (
	FilterExpressionOperatorAfter              FilterExpressionOperator = "after"
	FilterExpressionOperatorBefore             FilterExpressionOperator = "before"
	FilterExpressionOperatorContains           FilterExpressionOperator = "contains"
	FilterExpressionOperatorDoesNotContain     FilterExpressionOperator = "doesNotContain"
	FilterExpressionOperatorDoesNotEqual       FilterExpressionOperator = "doesNotEqual"
	FilterExpressionOperatorEndsWith           FilterExpressionOperator = "endsWith"
	FilterExpressionOperatorEquals             FilterExpressionOperator = "equals"
	FilterExpressionOperatorGreaterThan        FilterExpressionOperator = ">"
	FilterExpressionOperatorGreaterThanOrEqual FilterExpressionOperator = ">="
	FilterExpressionOperatorIsAnyOf            FilterExpressionOperator = "isAnyOf"
	FilterExpressionOperatorIsEmpty            FilterExpressionOperator = "isEmpty"
	FilterExpressionOperatorIsNotEmpty         FilterExpressionOperator = "isNotEmpty"
	FilterExpressionOperatorLessThan           FilterExpressionOperator = "<"
	FilterExpressionOperatorLessThanOrEqual    FilterExpressionOperator = "<="
	FilterExpressionOperatorOnOrAfter          FilterExpressionOperator = "onOrAfter"
	FilterExpressionOperatorOnOrBefore         FilterExpressionOperator = "onOrBefore"
	FilterExpressionOperatorStartsWith         FilterExpressionOperator = "startsWith"
)

func FilterExpressionOperatorFromField(field string) (_ FilterExpressionOperator, ok bool) {
	switch field {
	case "$after":
		return FilterExpressionOperatorAfter, true
	case "$before":
		return FilterExpressionOperatorBefore, true
	case "$contains":
		return FilterExpressionOperatorContains, true
	case "$doesNotContain":
		return FilterExpressionOperatorDoesNotContain, true
	case "!=", "$doesNotEqual":
		return FilterExpressionOperatorDoesNotEqual, true
	case "$endsWith":
		return FilterExpressionOperatorEndsWith, true
	case "=", "==", "$eq", "$equals", "$is":
		return FilterExpressionOperatorEquals, true
	case ">":
		return FilterExpressionOperatorGreaterThan, true
	case ">=":
		return FilterExpressionOperatorGreaterThanOrEqual, true
	case "$isAnyOf":
		return FilterExpressionOperatorIsAnyOf, true
	case "$isEmpty":
		return FilterExpressionOperatorIsEmpty, true
	case "$isNotEmpty":
		return FilterExpressionOperatorIsNotEmpty, true
	case "<":
		return FilterExpressionOperatorLessThan, true
	case "<=":
		return FilterExpressionOperatorLessThanOrEqual, true
	case "$onOrAfter":
		return FilterExpressionOperatorOnOrAfter, true
	case "$onOrBefore":
		return FilterExpressionOperatorOnOrBefore, true
	case "$startsWith":
		return FilterExpressionOperatorStartsWith, true
	}
	return "", false
}
