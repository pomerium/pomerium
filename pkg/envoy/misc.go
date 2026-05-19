package envoy

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func marshalAny(msg proto.Message) *anypb.Any {
	data := new(anypb.Any)
	_ = anypb.MarshalFrom(data, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return data
}

func firstNonEmpty[T interface{ ~string }](args ...T) T {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}
