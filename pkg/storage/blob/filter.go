package blob

import (
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/storage"
)

// MatchesFilterExpression evaluates a FilterExpression against a proto message.
// It converts the message to a map using protoreflect and then recursively
// evaluates the filter expression tree against the map values.
func matchesFilterExpression(msg proto.Message, expr storage.FilterExpression) (bool, error) {
	if expr == nil {
		return true, nil
	}
	m := storage.MsgToMap(msg.ProtoReflect())
	return matchesFilter(m, expr)
}

func matchesFilter(m map[string]any, expr storage.FilterExpression) (bool, error) {
	if expr == nil {
		return true, nil
	}
	switch e := expr.(type) {
	case storage.AndFilterExpression:
		for _, sub := range e {
			ok, err := matchesFilter(m, sub)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case storage.OrFilterExpression:
		for _, sub := range e {
			ok, err := matchesFilter(m, sub)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case storage.NotFilterExpression:
		ok, err := matchesFilter(m, e.FilterExpression)
		if err != nil {
			return false, err
		}
		return !ok, nil
	case storage.SimpleFilterExpression:
		return matchesSimpleFilter(m, e)
	default:
		return false, fmt.Errorf("unknown filter expression type: %T", expr)
	}
}

func matchesSimpleFilter(m map[string]any, expr storage.SimpleFilterExpression) (bool, error) {
	val := resolveFieldPath(m, expr.Fields)
	var valStr string
	if val != nil {
		valStr = fmt.Sprint(val)
	}
	exprVal := expr.ValueAsString()

	switch expr.Operator {
	case storage.FilterExpressionOperatorEquals:
		return valStr == exprVal, nil
	case storage.FilterExpressionOperatorDoesNotEqual:
		return valStr != exprVal, nil
	case storage.FilterExpressionOperatorContains:
		return strings.Contains(valStr, exprVal), nil
	case storage.FilterExpressionOperatorDoesNotContain:
		return !strings.Contains(valStr, exprVal), nil
	case storage.FilterExpressionOperatorStartsWith:
		return strings.HasPrefix(valStr, exprVal), nil
	case storage.FilterExpressionOperatorEndsWith:
		return strings.HasSuffix(valStr, exprVal), nil
	case storage.FilterExpressionOperatorIsEmpty:
		return val == nil || valStr == "", nil
	case storage.FilterExpressionOperatorIsNotEmpty:
		return val != nil && valStr != "", nil
	case storage.FilterExpressionOperatorIsAnyOf:
		return slices.Contains(expr.ValueAsStringSlice(), valStr), nil
	case storage.FilterExpressionOperatorGreaterThan:
		return valStr > exprVal, nil
	case storage.FilterExpressionOperatorGreaterThanOrEqual:
		return valStr >= exprVal, nil
	case storage.FilterExpressionOperatorLessThan:
		return valStr < exprVal, nil
	case storage.FilterExpressionOperatorLessThanOrEqual:
		return valStr <= exprVal, nil
	default:
		return false, fmt.Errorf("%w: %s", storage.ErrOperatorNotSupported, expr.Operator)
	}
}

// resolveFieldPath navigates a nested map using a field path (e.g., ["nested", "field"])
// and returns the value at that path, or nil if not found.
func resolveFieldPath(m map[string]any, fields []string) any {
	if len(fields) == 0 || m == nil {
		return nil
	}
	var current any = m
	for _, field := range fields {
		cm, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = cm[field]
		if !ok {
			return nil
		}
	}
	return current
}
