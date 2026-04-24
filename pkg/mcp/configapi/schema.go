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
