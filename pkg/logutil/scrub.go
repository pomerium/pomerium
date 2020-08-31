package logutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// A Scrubber scrubs potentially sensitive strings from protobuf messages.
type Scrubber struct {
	key       string
	whitelist map[string]struct{}
}

// NewScrubber creates a new Scrubber.
func NewScrubber(key string) *Scrubber {
	return &Scrubber{
		key:       key,
		whitelist: map[string]struct{}{},
	}
}

// Whitelist whitelists fields for a given type. The type name should be the full
// protobuf typename (ie google.protobuf.Any).
func (s *Scrubber) Whitelist(typeName string, fieldNames ...string) *Scrubber {
	for _, fieldName := range fieldNames {
		s.whitelist[typeName+"."+fieldName] = struct{}{}
	}
	return s
}

// ScrubProto takes in a protobuf message, clones it and scrubs any non-whitelisted strings.
func (s *Scrubber) ScrubProto(msg proto.Message) proto.Message {
	src := msg.ProtoReflect()
	dst := src.New()

	s.scrubProtoMessage(dst, src)

	return dst.Interface()
}

func (s *Scrubber) scrubProtoMessage(dst, src protoreflect.Message) {
	// most of this code is based on
	// https://github.com/protocolbuffers/protobuf-go/blob/v1.25.0/proto/merge.go
	if srcany, ok := src.Interface().(*anypb.Any); ok {
		if dstany, ok := dst.Interface().(*anypb.Any); ok {
			s.scrubProtoAny(dstany, srcany)
			return
		}
	}

	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		// skip whitelisted fields
		if _, ok := s.whitelist[string(fd.FullName())]; ok {
			dst.Set(fd, v)
			return true
		}

		switch {
		case fd.IsList():
			s.scrubProtoList(dst.Mutable(fd).List(), v.List(), fd)
		case fd.IsMap():
			s.scrubProtoMap(dst.Mutable(fd).Map(), v.Map(), fd.MapValue())
		case fd.Message() != nil:
			s.scrubProtoMessage(dst.Mutable(fd).Message(), v.Message())
		case fd.Kind() == protoreflect.BytesKind:
			nv := s.hmacBytes(v.Bytes())
			dst.Set(fd, protoreflect.ValueOfBytes(nv))
		case fd.Kind() == protoreflect.StringKind:
			nv := s.hmacString(v.String())
			dst.Set(fd, protoreflect.ValueOfString(nv))
		default:
			dst.Set(fd, v)
		}
		return true
	})

	if len(src.GetUnknown()) > 0 {
		dst.SetUnknown(append(dst.GetUnknown(), src.GetUnknown()...))
	}
}

func (s *Scrubber) scrubProtoAny(dst, src *anypb.Any) {
	msg, err := src.UnmarshalNew()
	if err != nil {
		// this will happen if a type isn't registered.
		// So we will just hash the raw data.
		a, _ := anypb.New(wrapperspb.Bytes(s.hmacBytes(src.Value)))
		dst.TypeUrl = a.TypeUrl
		dst.Value = a.Value
		return
	}

	srcmsg := msg.ProtoReflect()
	dstmsg := srcmsg.New()

	s.scrubProtoMessage(dstmsg, srcmsg)

	a, err := anypb.New(dstmsg.Interface())
	if err != nil {
		// this really shouldn't happen, but in case it does,
		// we hash the raw data as above.
		a, _ = anypb.New(wrapperspb.Bytes(s.hmacBytes(src.Value)))
	}
	dst.TypeUrl = a.TypeUrl
	dst.Value = a.Value
}

func (s *Scrubber) scrubProtoList(dst, src protoreflect.List, fd protoreflect.FieldDescriptor) {
	for i, n := 0, src.Len(); i < n; i++ {
		switch v := src.Get(i); {
		case fd.Message() != nil:
			dstv := dst.NewElement()
			s.scrubProtoMessage(dstv.Message(), v.Message())
			dst.Append(dstv)
		case fd.Kind() == protoreflect.BytesKind:
			nv := s.hmacBytes(v.Bytes())
			dst.Append(protoreflect.ValueOfBytes(nv))
		case fd.Kind() == protoreflect.StringKind:
			nv := s.hmacString(v.String())
			dst.Append(protoreflect.ValueOfString(nv))
		default:
			dst.Append(v)
		}
	}
}

func (s *Scrubber) scrubProtoMap(dst, src protoreflect.Map, fd protoreflect.FieldDescriptor) {
	src.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		switch {
		case fd.Message() != nil:
			dstv := dst.NewValue()
			s.scrubProtoMessage(dstv.Message(), v.Message())
			dst.Set(k, dstv)
		case fd.Kind() == protoreflect.BytesKind:
			nv := s.hmacBytes(v.Bytes())
			dst.Set(k, protoreflect.ValueOfBytes(nv))
		case fd.Kind() == protoreflect.StringKind:
			nv := s.hmacString(v.String())
			dst.Set(k, protoreflect.ValueOfString(nv))
		default:
			dst.Set(k, v)
		}
		return true
	})
}

func (s *Scrubber) hmacBytes(v []byte) []byte {
	h := hmac.New(sha256.New, []byte(s.key))
	return h.Sum(v)
}

func (s *Scrubber) hmacString(v string) string {
	return base64.StdEncoding.EncodeToString(s.hmacBytes([]byte(v)))
}
