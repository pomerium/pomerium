package storage

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/types/known/structpb"
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
	return filterExpressionFromEq(path, v)
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
		case "$eq":
			expr, err := filterExpressionFromEq(path, v)
			if err != nil {
				return nil, err
			}
			and = append(and, expr)
		default:
			expr, err := filterExpressionFromValue(append(path, f), v)
			if err != nil {
				return nil, err
			}
			and = append(and, expr)
		}
	}

	if len(and) == 1 {
		return and[0], nil
	}
	return and, nil
}

func filterExpressionFromEq(path []string, v *structpb.Value) (FilterExpression, error) {
	switch vv := v.GetKind().(type) {
	case *structpb.Value_BoolValue:
		return EqualsFilterExpression{
			Fields: path,
			Value:  fmt.Sprintf("%v", vv.BoolValue),
		}, nil
	case *structpb.Value_NullValue:
		return EqualsFilterExpression{
			Fields: path,
			Value:  fmt.Sprintf("%v", vv.NullValue),
		}, nil
	case *structpb.Value_NumberValue:
		return EqualsFilterExpression{
			Fields: path,
			Value:  fmt.Sprintf("%v", vv.NumberValue),
		}, nil
	case *structpb.Value_StringValue:
		return EqualsFilterExpression{
			Fields: path,
			Value:  vv.StringValue,
		}, nil
	}
	return nil, fmt.Errorf("unsupported struct value type for eq: %T", v.GetKind())
}

// An OrFilterExpression represents a logical-or comparison operator.
type OrFilterExpression []FilterExpression

func (OrFilterExpression) isFilterExpression() {}

// An AndFilterExpression represents a logical-and comparison operator.
type AndFilterExpression []FilterExpression

func (AndFilterExpression) isFilterExpression() {}

// An EqualsFilterExpression represents a field comparison operator.
type EqualsFilterExpression struct {
	Fields []string
	Value  string
}

func (EqualsFilterExpression) isFilterExpression() {}
