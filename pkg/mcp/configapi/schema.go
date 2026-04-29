// Package configapi exposes pomerium's ConfigService as Model Context Protocol
// tools. Tools are auto-discovered via protobuf reflection from
// config.File_config_proto; input/output JSON Schemas are derived from the
// protobuf message descriptors and dispatched to a supplied
// configconnect.ConfigServiceHandler in-process.
package configapi

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
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
	props["_meta"] = metaSchema()
	return schema
}

func metaSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"description": "MCP response metadata. This object is added by the MCP " +
			"layer; it is not part of the underlying entity. Surface it to the " +
			"end user when explaining what was returned.",
		"properties": map[string]any{
			"scrubbedFields": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
				"description": "JSON paths of sensitive fields that ARE configured " +
					"on the returned entity but whose values were redacted from this " +
					"response (e.g. 'route.idpClientSecret'). Tell the user these " +
					"fields are set and that the values cannot be viewed via MCP — " +
					"direct them to links.canonical to inspect or change them.",
			},
			"links": map[string]any{
				"type": "object",
				"additionalProperties": map[string]any{
					"type":   "string",
					"format": "uri",
				},
				"description": "URLs related to this response. links.canonical is " +
					"the admin-UI page where the entity (and any redacted sensitive " +
					"fields) can be viewed or edited.",
			},
		},
	}
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

	return map[string]any{
		"type":       "object",
		"properties": props,
	}
}

func fieldToSchema(fd protoreflect.FieldDescriptor, visited map[protoreflect.FullName]bool) map[string]any {
	if fd.IsMap() {
		valueField := fd.MapValue()
		return map[string]any{
			"type":                 "object",
			"additionalProperties": scalarOrMessageSchema(valueField, visited),
		}
	}

	schema := scalarOrMessageSchema(fd, visited)

	if fd.IsList() {
		return map[string]any{
			"type":  "array",
			"items": schema,
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

func enumSchema(ed protoreflect.EnumDescriptor) map[string]any {
	values := ed.Values()
	names := make([]any, 0, values.Len())
	for i := range values.Len() {
		names = append(names, string(values.Get(i).Name()))
	}
	return map[string]any{
		"type":        "string",
		"enum":        names,
		"description": fmt.Sprintf("enum %s", ed.FullName()),
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
