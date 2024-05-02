// Package protoutil contains functions for working with protobuf types.
package protoutil

import (
	"fmt"
	"reflect"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToStruct converts any value into a structpb Value.
func ToStruct(value any) *structpb.Value {
	if value == nil {
		return NewStructNull()
	}

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
	}

	if msg, ok := value.(proto.Message); ok {
		bs, _ := protojson.Marshal(msg)
		var s structpb.Struct
		_ = protojson.Unmarshal(bs, &s)
		return &structpb.Value{
			Kind: &structpb.Value_StructValue{StructValue: &s},
		}
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Slice:
		svs := make([]*structpb.Value, rv.Len())
		for i := range svs {
			svs[i] = ToStruct(rv.Index(i).Interface())
		}
		return NewStructList(svs...)
	case reflect.Map:
		svm := make(map[string]*structpb.Value)
		iter := rv.MapRange()
		for iter.Next() {
			svm[fmt.Sprint(iter.Key().Interface())] = ToStruct(iter.Value().Interface())
		}
		return NewStructMap(svm)
	}

	return NewStructNull()
}

// NewStructBool creates a new bool struct value.
func NewStructBool(v bool) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_BoolValue{BoolValue: v},
	}
}

// NewStructMap creates a new map struct value.
func NewStructMap(v map[string]*structpb.Value) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: v}},
	}
}

// NewStructNull creates a new null struct value.
func NewStructNull() *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_NullValue{},
	}
}

// NewStructNumber creates a new number struct value.
func NewStructNumber(v float64) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_NumberValue{NumberValue: v},
	}
}

// NewStructList creates a new list struct value.
func NewStructList(vs ...*structpb.Value) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: vs}},
	}
}

// NewStructString creates a new string struct value.
func NewStructString(v string) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StringValue{StringValue: v},
	}
}
