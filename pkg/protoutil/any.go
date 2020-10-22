package protoutil

import (
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ToAny converts any type into an any value.
func ToAny(value interface{}) *anypb.Any {
	switch v := value.(type) {
	case bool:
		return NewAnyBool(v)
	case []byte:
		return NewAnyBytes(v)
	case float32:
		return NewAnyFloat(v)
	case float64:
		return NewAnyDouble(v)
	case int:
		return NewAnyInt64(int64(v))
	case int8:
		return NewAnyInt32(int32(v))
	case int16:
		return NewAnyInt32(int32(v))
	case int32:
		return NewAnyInt32(v)
	case int64:
		return NewAnyInt64(v)
	case string:
		return NewAnyString(v)
	case uint:
		return NewAnyUInt64(uint64(v))
	case uint8:
		return NewAnyUInt32(uint32(v))
	case uint16:
		return NewAnyUInt32(uint32(v))
	case uint32:
		return NewAnyUInt32(v)
	case uint64:
		return NewAnyUInt64(v)
	default:
		a, err := anypb.New(ToStruct(value))
		if err != nil {
			return NewAnyNull()
		}
		return a
	}
}

// NewAnyBool creates a new any type from a bool.
func NewAnyBool(v bool) *anypb.Any {
	a, _ := anypb.New(wrapperspb.Bool(v))
	return a
}

// NewAnyBytes creates a new any type from bytes.
func NewAnyBytes(v []byte) *anypb.Any {
	a, _ := anypb.New(wrapperspb.Bytes(v))
	return a
}

// NewAnyDouble creates a new any type from a float64.
func NewAnyDouble(v float64) *anypb.Any {
	a, _ := anypb.New(wrapperspb.Double(v))
	return a
}

// NewAnyFloat creates a new any type from a float32.
func NewAnyFloat(v float32) *anypb.Any {
	a, _ := anypb.New(wrapperspb.Float(v))
	return a
}

// NewAnyInt64 creates a new any type from an int64.
func NewAnyInt64(v int64) *anypb.Any {
	a, _ := anypb.New(wrapperspb.Int64(v))
	return a
}

// NewAnyInt32 creates a new any type from an int32.
func NewAnyInt32(v int32) *anypb.Any {
	a, _ := anypb.New(wrapperspb.Int32(v))
	return a
}

// NewAnyNull creates a new any type from a null struct.
func NewAnyNull() *anypb.Any {
	a, _ := anypb.New(NewStructNull())
	return a
}

// NewAnyString creates a new any type from a string.
func NewAnyString(v string) *anypb.Any {
	a, _ := anypb.New(wrapperspb.String(v))
	return a
}

// NewAnyUInt64 creates a new any type from an uint64.
func NewAnyUInt64(v uint64) *anypb.Any {
	a, _ := anypb.New(wrapperspb.UInt64(v))
	return a
}

// NewAnyUInt32 creates a new any type from an uint32.
func NewAnyUInt32(v uint32) *anypb.Any {
	a, _ := anypb.New(wrapperspb.UInt32(v))
	return a
}
