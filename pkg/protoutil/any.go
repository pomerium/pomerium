package protoutil

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
		return NewAny(ToStruct(value))
	}
}

// NewAny creates a new Any using deterministic serialization.
func NewAny(msg proto.Message) *anypb.Any {
	a := new(anypb.Any)
	err := anypb.MarshalFrom(a, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	if err != nil {
		// on error, which doesn't really happen in practice, return null
		return NewAnyNull()
	}
	return a
}

// UnmarshalAnyJSON unmarshals JSON data into Any
func UnmarshalAnyJSON(data []byte) (*anypb.Any, error) {
	opts := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}
	var val anypb.Any
	if err := opts.Unmarshal(data, &val); err != nil {
		return nil, err
	}
	return &val, nil
}

// NewAnyBool creates a new any type from a bool.
func NewAnyBool(v bool) *anypb.Any {
	return NewAny(wrapperspb.Bool(v))
}

// NewAnyBytes creates a new any type from bytes.
func NewAnyBytes(v []byte) *anypb.Any {
	return NewAny(wrapperspb.Bytes(v))
}

// NewAnyDouble creates a new any type from a float64.
func NewAnyDouble(v float64) *anypb.Any {
	return NewAny(wrapperspb.Double(v))
}

// NewAnyFloat creates a new any type from a float32.
func NewAnyFloat(v float32) *anypb.Any {
	return NewAny(wrapperspb.Float(v))
}

// NewAnyInt64 creates a new any type from an int64.
func NewAnyInt64(v int64) *anypb.Any {
	return NewAny(wrapperspb.Int64(v))
}

// NewAnyInt32 creates a new any type from an int32.
func NewAnyInt32(v int32) *anypb.Any {
	return NewAny(wrapperspb.Int32(v))
}

// NewAnyNull creates a new any type from a null struct.
func NewAnyNull() *anypb.Any {
	return NewAny(NewStructNull())
}

// NewAnyString creates a new any type from a string.
func NewAnyString(v string) *anypb.Any {
	return NewAny(wrapperspb.String(v))
}

// NewAnyUInt64 creates a new any type from an uint64.
func NewAnyUInt64(v uint64) *anypb.Any {
	return NewAny(wrapperspb.UInt64(v))
}

// NewAnyUInt32 creates a new any type from an uint32.
func NewAnyUInt32(v uint32) *anypb.Any {
	return NewAny(wrapperspb.UInt32(v))
}

// GetTypeURL gets the TypeURL for a protobuf message.
func GetTypeURL(msg proto.Message) string {
	// taken from the anypb package
	const urlPrefix = "type.googleapis.com/"
	return urlPrefix + string(msg.ProtoReflect().Descriptor().FullName())
}
