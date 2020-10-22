// Package protoutil contains functions for working with protobuf types.
package protoutil

import (
	structpb "github.com/golang/protobuf/ptypes/struct"
)

// ToStruct converts any value into a structpb Value.
func ToStruct(value interface{}) *structpb.Value {
	switch v := value.(type) {
	case bool:
		return NewStructBool(v)
	case float64:
		return NewStructNumber(v)
	case float32:
		return NewStructNumber(float64(v))
	case int:
		return NewStructNumber(float64(v))
	case int8:
		return NewStructNumber(float64(v))
	case int16:
		return NewStructNumber(float64(v))
	case int32:
		return NewStructNumber(float64(v))
	case int64:
		return NewStructNumber(float64(v))
	case string:
		return NewStructString(v)
	case uint:
		return NewStructNumber(float64(v))
	case uint8:
		return NewStructNumber(float64(v))
	case uint16:
		return NewStructNumber(float64(v))
	case uint32:
		return NewStructNumber(float64(v))
	case uint64:
		return NewStructNumber(float64(v))
	case []interface{}:
		svs := make([]*structpb.Value, len(v))
		for i := range v {
			svs[i] = ToStruct(v[i])
		}
		return NewStructList(svs...)
	default:
		return NewStructNull()
	}
}

// NewStructBool creates a new bool struct value.
func NewStructBool(v bool) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_BoolValue{BoolValue: v},
	}
}

// NewStructNumber creates a new number struct value.
func NewStructNumber(v float64) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_NumberValue{NumberValue: v},
	}
}

// NewStructString creates a new string struct value.
func NewStructString(v string) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StringValue{StringValue: v},
	}
}

// NewStructList creates a new list struct value.
func NewStructList(vs ...*structpb.Value) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: vs}},
	}
}

// NewStructNull creates a new null struct value.
func NewStructNull() *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_NullValue{},
	}
}
