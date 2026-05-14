package configapi

import (
	"sort"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// IsSensitive reports whether fd carries the (pomerium.config.sensitive)
// option. Sensitive fields are stripped from MCP request/response schemas,
// scrubbed from response payloads, and copied from the existing record on
// Update*.
func IsSensitive(fd protoreflect.FieldDescriptor) bool {
	v, ok := proto.GetExtension(fd.Options(), configpb.E_Sensitive).(bool)
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

// SensitiveFieldsSet walks msg and returns the JSON-name paths of sensitive
// fields whose value is present (Has() == true). Paths use protojson field
// names, matching the JSON the MCP client sees. List/map elements that
// carry a sensitive sub-field collapse to a glob ("certificates[].keyBytes")
// rather than per-index paths, which would balloon under large lists and
// don't tell the LLM anything actionable beyond "some elements have it".
//
// Returns nil when no sensitive fields are populated. Result is sorted for
// stable presentation.
func SensitiveFieldsSet(msg proto.Message) []string {
	if msg == nil {
		return nil
	}
	out := map[string]struct{}{}
	collectSensitive(msg.ProtoReflect(), "", out)
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

func collectSensitive(m protoreflect.Message, prefix string, out map[string]struct{}) {
	if !m.IsValid() {
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
			m.Get(fd).Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				collectSensitive(v.Message(), child, out)
				return true
			})
		case fd.IsList():
			if fd.Kind() != protoreflect.MessageKind {
				continue
			}
			child := joinPath(path, "[]")
			list := m.Get(fd).List()
			for i := 0; i < list.Len(); i++ {
				collectSensitive(list.Get(i).Message(), child, out)
			}
		case fd.Kind() == protoreflect.MessageKind:
			collectSensitive(m.Get(fd).Message(), path, out)
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
