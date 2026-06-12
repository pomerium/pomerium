package protoutil

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// Redacted is the placeholder value substituted for string and bytes fields
// annotated with [(pomerium.config.sensitive) = true].
const Redacted = "[REDACTED]"

var anyFullName = (&anypb.Any{}).ProtoReflect().Descriptor().FullName()

// RedactSensitive walks msg in place and redacts every field annotated with
// [(pomerium.config.sensitive) = true]. String and bytes values (including
// list elements and map values) are replaced with the Redacted placeholder so
// a reader can tell the field was set; values of any other kind are cleared.
// google.protobuf.Any fields are unpacked, redacted, and re-packed; Any
// payloads whose type is not registered are left untouched.
func RedactSensitive(msg proto.Message) {
	if msg == nil {
		return
	}
	redactMessage(msg.ProtoReflect())
}

func redactMessage(m protoreflect.Message) {
	if !m.IsValid() {
		return
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if !m.Has(fd) {
			continue
		}
		if IsSensitive(fd) {
			redactField(m, fd)
			continue
		}
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() != protoreflect.MessageKind {
				continue
			}
			m.Get(fd).Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				redactMessageValue(v.Message())
				return true
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind {
				continue
			}
			list := m.Get(fd).List()
			for i := 0; i < list.Len(); i++ {
				redactMessageValue(list.Get(i).Message())
			}
		case fd.Kind() == protoreflect.MessageKind:
			redactMessageValue(m.Mutable(fd).Message())
		}
	}
}

// redactMessageValue redacts a nested message, special-casing
// google.protobuf.Any by unpacking, redacting, and re-packing its payload.
func redactMessageValue(m protoreflect.Message) {
	if m.Descriptor().FullName() == anyFullName {
		redactAny(m)
		return
	}
	redactMessage(m)
}

func redactAny(m protoreflect.Message) {
	fds := m.Descriptor().Fields()
	typeURLFD := fds.ByName("type_url")
	valueFD := fds.ByName("value")

	typeURL := m.Get(typeURLFD).String()
	if typeURL == "" {
		return
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByURL(typeURL)
	if err != nil {
		// unknown payload type: nothing to inspect; leave it as is
		return
	}
	inner := mt.New().Interface()
	if err := proto.Unmarshal(m.Get(valueFD).Bytes(), inner); err != nil {
		return
	}
	redactMessage(inner.ProtoReflect())
	bs, err := proto.Marshal(inner)
	if err != nil {
		return
	}
	m.Set(valueFD, protoreflect.ValueOfBytes(bs))
}

// redactField overwrites a sensitive field that is set. String and bytes
// values become the Redacted placeholder; other kinds are cleared since they
// have no meaningful placeholder representation.
func redactField(m protoreflect.Message, fd protoreflect.FieldDescriptor) {
	switch {
	case fd.IsMap():
		mv := fd.MapValue()
		if v, ok := redactedScalar(mv.Kind()); ok {
			mm := m.Mutable(fd).Map()
			mm.Range(func(k protoreflect.MapKey, _ protoreflect.Value) bool {
				mm.Set(k, v)
				return true
			})
			return
		}
		m.Clear(fd)
	case fd.IsList():
		if v, ok := redactedScalar(fd.Kind()); ok {
			list := m.Mutable(fd).List()
			for i := 0; i < list.Len(); i++ {
				list.Set(i, v)
			}
			return
		}
		m.Clear(fd)
	default:
		if v, ok := redactedScalar(fd.Kind()); ok {
			m.Set(fd, v)
			return
		}
		m.Clear(fd)
	}
}

func redactedScalar(kind protoreflect.Kind) (protoreflect.Value, bool) {
	switch kind {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(Redacted), true
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(Redacted)), true
	default:
		return protoreflect.Value{}, false
	}
}

// IsSensitive reports whether fd carries the (pomerium.config.sensitive)
// field option.
func IsSensitive(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), configpb.E_Sensitive).(bool)
	return ok && v
}
