// Package configapi exposes pomerium's ConfigService as Model Context Protocol
// tools. Tools are auto-discovered via protobuf reflection from
// config.File_config_proto; input/output JSON Schemas are derived from the
// protobuf message descriptors and dispatched to a supplied
// configconnect.ConfigServiceHandler in-process.
package configapi

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// messageToJSONSchema converts a protobuf MessageDescriptor to a JSON Schema
// object suitable for use as mcp.Tool InputSchema/OutputSchema.
// It uses protobuf JSON field names (camelCase) since protojson serialization is used.
func messageToJSONSchema(md protoreflect.MessageDescriptor) map[string]any {
	return msgToSchema(md, make(map[protoreflect.FullName]bool))
}

// outputSchema returns the JSON Schema for a method's output, augmented
// with the _meta property the registry attaches to every successful tool
// response. Documenting the field in-schema lets the LLM understand it is
// part of the contract, not noise — clients that render structured output
// are expected to surface scrubbedFields and links.canonical to the user.
func outputSchema(md protoreflect.MessageDescriptor) map[string]any {
	schema := msgToSchema(md, make(map[protoreflect.FullName]bool))
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		props = map[string]any{}
		schema["properties"] = props
	}
	props["_meta"] = metaSchema
	return schema
}

// metaSchema is the fixed JSON Schema for the _meta object every MCP
// tool response carries. It's a constant by construction, so build it
// once at package init.
var metaSchema = map[string]any{
	"type": "object",
	"description": "Metadata about the response itself, distinct from the " +
		"entity. Surface it to the user when explaining what was returned.",
	"properties": map[string]any{
		"scrubbedFields": map[string]any{
			"type":  "array",
			"items": map[string]any{"type": "string"},
			"description": "JSON paths of sensitive fields that have values " +
				"configured on this entity but whose values are not shown here " +
				"(e.g. 'route.idpClientSecret'). Tell the user these fields are " +
				"set; they can retrieve or change the values from the console at " +
				"links.canonical.",
		},
		"links": map[string]any{
			"type": "object",
			"additionalProperties": map[string]any{
				"type":   "string",
				"format": "uri",
			},
			"description": "URLs related to this response. links.canonical is " +
				"the page in the Pomerium console where the user can view or " +
				"change this entity, including any sensitive fields named in " +
				"scrubbedFields.",
		},
	},
}

func msgToSchema(md protoreflect.MessageDescriptor, visited map[protoreflect.FullName]bool) map[string]any {
	if schema, ok := wellKnownTypeSchema(md.FullName()); ok {
		return schema
	}

	if visited[md.FullName()] {
		return map[string]any{"type": "object"}
	}
	visited[md.FullName()] = true
	defer delete(visited, md.FullName())

	props := map[string]any{}
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if IsSensitive(fd) {
			continue
		}
		props[fd.JSONName()] = fieldToSchema(fd, visited)
	}

	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if d := configpb.MessageDescription(md); d != "" {
		schema["description"] = d
	}
	return schema
}

// fieldToSchema attaches the field's leading-comment doc (from config.proto)
// to the schema for the field itself. For a scalar that lands directly on
// the property; for a list/map it lands on the container so the LLM sees
// the description next to the field name, not buried inside `items`.
func fieldToSchema(fd protoreflect.FieldDescriptor, visited map[protoreflect.FullName]bool) map[string]any {
	desc := configpb.FieldDescription(fd)

	if fd.IsMap() {
		valueField := fd.MapValue()
		out := map[string]any{
			"type":                 "object",
			"additionalProperties": scalarOrMessageSchema(valueField, visited),
		}
		if desc != "" {
			out["description"] = desc
		}
		return out
	}

	schema := scalarOrMessageSchema(fd, visited)

	if fd.IsList() {
		out := map[string]any{
			"type":  "array",
			"items": schema,
		}
		if desc != "" {
			out["description"] = desc
		}
		return out
	}

	if desc != "" {
		// Singular scalar/message: merge the field doc onto the value schema.
		// scalarOrMessageSchema may have set its own "description" (e.g. for
		// 64-bit-int-as-string or bytes-as-base64); preserve that hint by
		// appending. Field-level doc comes first because it's the more
		// informative one for an LLM.
		if existing, ok := schema["description"].(string); ok && existing != "" {
			schema["description"] = desc + " (" + existing + ")"
		} else {
			schema["description"] = desc
		}
	}
	return schema
}

func scalarOrMessageSchema(fd protoreflect.FieldDescriptor, visited map[protoreflect.FullName]bool) map[string]any {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return map[string]any{"type": "boolean"}

	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return map[string]any{"type": "integer"}

	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		// protojson encodes 64-bit integers as strings
		return map[string]any{"type": "string", "description": "64-bit integer encoded as string"}

	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return map[string]any{"type": "number"}

	case protoreflect.StringKind:
		return map[string]any{"type": "string"}

	case protoreflect.BytesKind:
		return map[string]any{"type": "string", "description": "base64-encoded bytes"}

	case protoreflect.EnumKind:
		return enumSchema(fd.Enum())

	case protoreflect.MessageKind, protoreflect.GroupKind:
		return msgToSchema(fd.Message(), visited)

	default:
		return map[string]any{}
	}
}

// enumSchema renders a protobuf enum as a JSON Schema string with the legal
// values listed under `enum`. JSON Schema has no standard slot for per-value
// docs, so any per-value leading comments from config.proto are appended to
// the schema's `description` as "VALUE_NAME: comment" lines — an LLM picking
// a value sees what each one means, not just the constant name.
func enumSchema(ed protoreflect.EnumDescriptor) map[string]any {
	values := ed.Values()
	names := make([]any, 0, values.Len())
	var valueDocs []string
	for i := range values.Len() {
		v := values.Get(i)
		names = append(names, string(v.Name()))
		if d := configpb.EnumValueDescription(v); d != "" {
			valueDocs = append(valueDocs, string(v.Name())+": "+d)
		}
	}

	var parts []string
	if d := configpb.EnumDescription(ed); d != "" {
		parts = append(parts, d)
	}
	parts = append(parts, fmt.Sprintf("(enum %s)", ed.FullName()))
	if len(valueDocs) > 0 {
		parts = append(parts, "Values: "+strings.Join(valueDocs, "; "))
	}

	return map[string]any{
		"type":        "string",
		"enum":        names,
		"description": strings.Join(parts, " "),
	}
}

func wellKnownTypeSchema(fullName protoreflect.FullName) (map[string]any, bool) {
	switch fullName {
	case "google.protobuf.Timestamp":
		return map[string]any{"type": "string", "format": "date-time"}, true
	case "google.protobuf.Duration":
		return map[string]any{"type": "string", "description": "Duration (e.g. '1.5s')"}, true
	case "google.protobuf.StringValue":
		return map[string]any{"type": "string"}, true
	case "google.protobuf.Int32Value", "google.protobuf.Int64Value",
		"google.protobuf.UInt32Value", "google.protobuf.UInt64Value":
		return map[string]any{"type": "integer"}, true
	case "google.protobuf.FloatValue", "google.protobuf.DoubleValue":
		return map[string]any{"type": "number"}, true
	case "google.protobuf.BoolValue":
		return map[string]any{"type": "boolean"}, true
	case "google.protobuf.Struct":
		return map[string]any{"type": "object"}, true
	case "google.protobuf.Value":
		return map[string]any{}, true
	case "google.protobuf.ListValue":
		return map[string]any{"type": "array"}, true
	case "google.protobuf.Empty":
		return map[string]any{"type": "object"}, true
	default:
		return nil, false
	}
}
