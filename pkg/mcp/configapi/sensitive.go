package configapi

import (
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

const (
	// Any payloads are recursively decoded so descriptor annotations inside the
	// payload cannot bypass sensitive-field scrubbing. Bound both nesting and
	// cumulative encoded input to keep presentation paths from becoming an
	// allocation or stack-exhaustion surface. Payloads outside either bound are
	// cleared by ScrubSensitive.
	maxSensitiveAnyDepth = 16
	maxSensitiveAnyBytes = 5 << 20
)

const anyMessageFullName protoreflect.FullName = "google.protobuf.Any"

type sensitiveTraversal struct {
	anyBytes int
}

var sensitiveConfigMessageDescriptors = func() map[protoreflect.FullName]protoreflect.MessageDescriptor {
	descriptors := make(map[protoreflect.FullName]protoreflect.MessageDescriptor)
	var add func(protoreflect.MessageDescriptors)
	add = func(messages protoreflect.MessageDescriptors) {
		for i := 0; i < messages.Len(); i++ {
			message := messages.Get(i)
			descriptors[message.FullName()] = message
			add(message.Messages())
		}
	}
	add(configpb.File_config_proto.Messages())
	return descriptors
}()

// IsSensitive reports whether fd carries the (pomerium.config.sensitive)
// option. Sensitive fields are stripped from MCP request/response schemas,
// scrubbed from response payloads, and copied from the existing record on
// Update*.
func IsSensitive(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), configpb.E_Sensitive).(bool)
	return ok && v
}

// ScrubSensitive walks msg recursively and clears every field whose
// descriptor is marked sensitive. Maps, lists, and bounded google.protobuf.Any
// payloads are descended; scalar sensitive fields are cleared via
// Message.Clear; sensitive message-typed fields are cleared rather than
// recursed. Any payloads that cannot be inspected safely are cleared.
func ScrubSensitive(msg proto.Message) {
	if msg == nil {
		return
	}
	scrubMessage(msg.ProtoReflect(), 0, new(sensitiveTraversal))
}

func scrubMessage(m protoreflect.Message, anyDepth int, traversal *sensitiveTraversal) {
	if !m.IsValid() {
		return
	}
	// Unknown wire fields have no descriptor options, so version-skewed fields
	// cannot be classified as safe. Drop them on every known message before any
	// presentation serialization.
	m.SetUnknown(nil)
	if m.Descriptor().FullName() == anyMessageFullName {
		embedded, ok := traversal.unpackAny(m, anyDepth)
		if !ok {
			clearAnyValue(m)
			return
		}
		if embedded == nil {
			return
		}
		scrubMessage(embedded.ProtoReflect(), anyDepth+1, traversal)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(embedded)
		if err != nil || len(encoded) > maxSensitiveAnyBytes {
			clearAnyValue(m)
			return
		}
		setAnyValue(m, encoded)
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
			rangeMessageMap(m.Get(fd).Map(), fd.MapKey().Kind(), func(_ protoreflect.MapKey, v protoreflect.Value) {
				scrubMessage(v.Message(), anyDepth, traversal)
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind {
				continue
			}
			list := m.Get(fd).List()
			for i := 0; i < list.Len(); i++ {
				scrubMessage(list.Get(i).Message(), anyDepth, traversal)
			}
		case fd.Kind() == protoreflect.MessageKind:
			scrubMessage(m.Get(fd).Message(), anyDepth, traversal)
		}
	}
}

func (traversal *sensitiveTraversal) unpackAny(
	m protoreflect.Message,
	anyDepth int,
) (proto.Message, bool) {
	if anyDepth >= maxSensitiveAnyDepth {
		return nil, false
	}
	fields := m.Descriptor().Fields()
	typeURLField := fields.ByName("type_url")
	valueField := fields.ByName("value")
	if typeURLField == nil || valueField == nil || !m.Has(valueField) {
		return nil, true
	}
	value := m.Get(valueField).Bytes()
	if len(value) > maxSensitiveAnyBytes-traversal.anyBytes {
		return nil, false
	}
	traversal.anyBytes += len(value)
	if !m.Has(typeURLField) {
		return nil, false
	}
	messageType, err := sensitiveAnyMessageType(m.Get(typeURLField).String())
	if err != nil {
		return nil, false
	}
	embedded := messageType.New().Interface()
	err = (proto.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
		Resolver:       protoregistry.GlobalTypes,
	}).Unmarshal(value, embedded)
	if err != nil {
		return nil, false
	}
	return embedded, true
}

func sensitiveAnyMessageType(typeURL string) (protoreflect.MessageType, error) {
	name := typeURL
	if index := strings.LastIndexByte(name, '/'); index >= 0 {
		name = name[index+1:]
	}
	if descriptor := sensitiveConfigMessageDescriptors[protoreflect.FullName(name)]; descriptor != nil {
		// Prefer the config descriptor compiled into this module. A duplicate
		// global protobuf registration can otherwise resolve an equivalent type
		// whose field options omit our sensitive annotation.
		return dynamicpb.NewMessageType(descriptor), nil
	}
	return protoregistry.GlobalTypes.FindMessageByURL(typeURL)
}

func clearAnyValue(m protoreflect.Message) {
	if valueField := m.Descriptor().Fields().ByName("value"); valueField != nil {
		m.Clear(valueField)
	}
}

func setAnyValue(m protoreflect.Message, value []byte) {
	if valueField := m.Descriptor().Fields().ByName("value"); valueField != nil {
		m.Set(valueField, protoreflect.ValueOfBytes(value))
	}
}

func rangeMessageMap(
	m protoreflect.Map,
	keyKind protoreflect.Kind,
	fn func(protoreflect.MapKey, protoreflect.Value),
) {
	keys := make([]protoreflect.MapKey, 0, m.Len())
	m.Range(func(key protoreflect.MapKey, _ protoreflect.Value) bool {
		keys = append(keys, key)
		return true
	})
	sort.Slice(keys, func(i, j int) bool {
		switch keyKind {
		case protoreflect.BoolKind:
			return !keys[i].Bool() && keys[j].Bool()
		case protoreflect.StringKind:
			return keys[i].String() < keys[j].String()
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
			protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			return keys[i].Int() < keys[j].Int()
		default:
			return keys[i].Uint() < keys[j].Uint()
		}
	})
	for _, key := range keys {
		fn(key, m.Get(key))
	}
}

// SensitiveFieldsSet walks msg and returns the JSON-name paths of sensitive
// fields whose value is present (Has() == true). Paths use protojson field
// names, matching the JSON the MCP client sees. List/map elements that
// carry a sensitive sub-field collapse to a glob ("certificates[].keyBytes")
// rather than per-index paths, which would balloon under large lists and
// don't tell the LLM anything actionable beyond "some elements have it".
// Bounded google.protobuf.Any payloads are transparent to path construction;
// payloads that cannot be inspected safely contribute no paths and are cleared
// by the subsequent ScrubSensitive pass. Unknown wire fields likewise
// contribute no paths and are removed by ScrubSensitive because their missing
// descriptors make sensitivity impossible to determine safely.
//
// Returns nil when no sensitive fields are populated. Result is sorted for
// stable presentation.
func SensitiveFieldsSet(msg proto.Message) []string {
	if msg == nil {
		return nil
	}
	out := map[string]struct{}{}
	collectSensitive(msg.ProtoReflect(), "", 0, new(sensitiveTraversal), out)
	if len(out) == 0 {
		return nil
	}
	paths := make([]string, 0, len(out))
	for p := range out {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func collectSensitive(
	m protoreflect.Message,
	prefix string,
	anyDepth int,
	traversal *sensitiveTraversal,
	out map[string]struct{},
) {
	if !m.IsValid() {
		return
	}
	if m.Descriptor().FullName() == anyMessageFullName {
		embedded, ok := traversal.unpackAny(m, anyDepth)
		if !ok || embedded == nil {
			return
		}
		collectSensitive(embedded.ProtoReflect(), prefix, anyDepth+1, traversal, out)
		return
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		path := joinPath(prefix, fd.JSONName())

		if IsSensitive(fd) {
			if !m.Has(fd) {
				continue
			}
			// Sensitive scalars and bytes always count as set when Has reports
			// true. For sensitive lists/maps, treat any non-empty container as
			// "set"; we don't try to express a per-element glob here because
			// the field itself is the secret-bearing surface.
			out[path] = struct{}{}
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
			child := joinPath(path, "[]")
			rangeMessageMap(m.Get(fd).Map(), fd.MapKey().Kind(), func(_ protoreflect.MapKey, v protoreflect.Value) {
				collectSensitive(v.Message(), child, anyDepth, traversal, out)
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind {
				continue
			}
			child := joinPath(path, "[]")
			list := m.Get(fd).List()
			for i := 0; i < list.Len(); i++ {
				collectSensitive(list.Get(i).Message(), child, anyDepth, traversal, out)
			}
		case fd.Kind() == protoreflect.MessageKind:
			collectSensitive(m.Get(fd).Message(), path, anyDepth, traversal, out)
		}
	}
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "[]" {
		return parent + "[]"
	}
	return parent + "." + child
}
