package protoutil

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
	"google.golang.org/protobuf/types/descriptorpb"
)

// this is copied from config.proto to avoid cyclical dependencies
var sensitiveExtension = &protoimpl.ExtensionInfo{
	ExtendedType:  (*descriptorpb.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         91501,
	Name:          "pomerium.config.sensitive",
	Tag:           "varint,91501,opt,name=sensitive",
	Filename:      "options.proto",
}

// IsSensitive returns true if the field is marked as sensitive.
func IsSensitive(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), sensitiveExtension).(bool)
	return ok && v
}

// ScrubSensitive walks msg recursively and clears every field whose
// descriptor is marked sensitive. Maps and lists are descended; scalar
// sensitive fields are cleared via Message.Clear; sensitive message-typed
// fields are cleared rather than recursed.
func ScrubSensitive(msg proto.Message) {
	if msg == nil {
		return
	}
	scrubMessage(msg.ProtoReflect())
}

func scrubMessage(m protoreflect.Message) {
	if !m.IsValid() {
		return
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if IsSensitive(fd) {
			m.Clear(fd)
			continue
		}
		if !m.Has(fd) {
			continue
		}
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() != protoreflect.MessageKind {
				continue
			}
			m.Get(fd).Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				scrubMessage(v.Message())
				return true
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind {
				continue
			}
			list := m.Get(fd).List()
			for i := 0; i < list.Len(); i++ {
				scrubMessage(list.Get(i).Message())
			}
		case fd.Kind() == protoreflect.MessageKind:
			scrubMessage(m.Get(fd).Message())
		}
	}
}
