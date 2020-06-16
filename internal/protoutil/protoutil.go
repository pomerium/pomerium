package protoutil

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// AnyToInterface converts an any type into a go-native interface.
func AnyToInterface(any *anypb.Any) interface{} {
	if any == nil {
		return nil
	}

	// basic wrapped types
	switch any.GetTypeUrl() {
	case "type.googleapis.com/google.protobuf.BoolValue":
		var v wrapperspb.BoolValue
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.BytesValue":
		var v wrapperspb.BytesValue
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.DoubleValue":
		var v wrapperspb.DoubleValue
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.FloatValue":
		var v wrapperspb.FloatValue
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.Int32Value":
		var v wrapperspb.Int32Value
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.Int64Value":
		var v wrapperspb.Int64Value
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.StringValue":
		var v wrapperspb.StringValue
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.UInt32Value":
		var v wrapperspb.UInt32Value
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	case "type.googleapis.com/google.protobuf.UInt64Value":
		var v wrapperspb.UInt64Value
		ptypes.UnmarshalAny(any, &v)
		return v.GetValue()
	}

	// all other message types
	messageType, err := protoregistry.GlobalTypes.FindMessageByURL(any.GetTypeUrl())
	if err != nil {
		return nil
	}
	msg := proto.MessageV1(messageType.New())
	err = ptypes.UnmarshalAny(any, msg)
	if err != nil {
		return nil
	}

	return msg
}
