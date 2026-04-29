package configapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// applyUpdatePatch implements sparse-patch semantics for Update* tool calls.
//
// The MCP request schema for the entity has sensitive fields removed, so the
// LLM cannot supply them. A naive Update would dispatch the request with
// those fields empty, wiping them in the DB. applyUpdatePatch fetches the
// existing entity via the matching Get* RPC and overlays only the fields the
// LLM explicitly set; sensitive fields and unset non-sensitive fields are
// preserved from the existing record.
//
// Returns the JSON to dispatch as the Update*. If the method does not match
// the Update* + Get* convention or the existing entity cannot be fetched,
// returns the original inputJSON unchanged with a non-nil ok=false so the
// caller can decide whether to proceed.
func applyUpdatePatch(
	ctx context.Context,
	caller *dynamicCaller,
	method protoreflect.MethodDescriptor,
	inputJSON json.RawMessage,
) (json.RawMessage, bool, error) {
	getMethod := findGetMethodForUpdate(method)
	if getMethod == nil {
		return inputJSON, false, nil
	}

	entityField := singleMessageField(method.Input())
	if entityField == nil {
		return inputJSON, false, nil
	}

	entityID := extractEntityIDFromJSON(inputJSON, entityField.JSONName())
	if entityID == "" {
		return inputJSON, false, nil
	}

	getReqJSON := fmt.Appendf(nil, `{"id":%q}`, entityID)
	getRespJSON, err := caller.call(ctx, getMethod, getReqJSON)
	if err != nil {
		return inputJSON, false, fmt.Errorf("fetching existing for sparse patch: %w", err)
	}

	getResponseEntityField := singleMessageField(getMethod.Output())
	if getResponseEntityField == nil ||
		getResponseEntityField.Message().FullName() != entityField.Message().FullName() {
		return inputJSON, false, nil
	}

	existingEntity := dynamicpb.NewMessage(getResponseEntityField.Message())
	if err := unmarshalNested(getRespJSON, getResponseEntityField.JSONName(), existingEntity); err != nil {
		return inputJSON, false, fmt.Errorf("decoding existing entity: %w", err)
	}

	incomingEntity := dynamicpb.NewMessage(entityField.Message())
	if err := unmarshalNested(inputJSON, entityField.JSONName(), incomingEntity); err != nil {
		return inputJSON, false, fmt.Errorf("decoding incoming entity: %w", err)
	}

	setKeys, err := presentKeysAtPath(inputJSON, entityField.JSONName())
	if err != nil {
		return inputJSON, false, fmt.Errorf("inspecting incoming JSON keys: %w", err)
	}

	merged := mergeFields(existingEntity, incomingEntity, setKeys)

	mergedReq := dynamicpb.NewMessage(method.Input())
	mergedReq.Set(entityField, protoreflect.ValueOfMessage(merged))
	out, err := protojson.Marshal(mergedReq)
	if err != nil {
		return inputJSON, false, fmt.Errorf("marshaling merged request: %w", err)
	}
	return out, true, nil
}

// findGetMethodForUpdate returns the Get<X> method that pairs with Update<X>
// in the same service, or nil if no such method exists.
func findGetMethodForUpdate(updateMethod protoreflect.MethodDescriptor) protoreflect.MethodDescriptor {
	name := string(updateMethod.Name())
	if !strings.HasPrefix(name, "Update") {
		return nil
	}
	getName := protoreflect.Name("Get" + name[len("Update"):])
	svc, ok := updateMethod.Parent().(protoreflect.ServiceDescriptor)
	if !ok {
		return nil
	}
	return svc.Methods().ByName(getName)
}

// singleMessageField returns the single non-repeated, non-map message-typed
// field of md, or nil if md does not have exactly one such field.
func singleMessageField(md protoreflect.MessageDescriptor) protoreflect.FieldDescriptor {
	var found protoreflect.FieldDescriptor
	count := 0
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.MessageKind {
			continue
		}
		if fd.IsList() || fd.IsMap() {
			continue
		}
		found = fd
		count++
	}
	if count != 1 {
		return nil
	}
	return found
}

// nestedFieldRaw returns the raw JSON for top.<topField> along with the
// decoded inner object (if it is one). Returning (nil, nil, nil) means the
// field is absent or empty input. err is non-nil only on malformed top-level
// JSON; a non-object inner value is reported as (raw, nil, nil).
func nestedFieldRaw(jsonBytes []byte, topField string) (json.RawMessage, map[string]json.RawMessage, error) {
	if len(jsonBytes) == 0 {
		return nil, nil, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &top); err != nil {
		return nil, nil, err
	}
	raw, ok := top[topField]
	if !ok {
		return nil, nil, nil
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inner); err != nil {
		return raw, nil, nil
	}
	return raw, inner, nil
}

// extractEntityIDFromJSON returns the value of the "id" key inside the given
// top-level JSON field, or "" if not present.
func extractEntityIDFromJSON(jsonBytes []byte, topField string) string {
	_, inner, err := nestedFieldRaw(jsonBytes, topField)
	if err != nil || inner == nil {
		return ""
	}
	var id string
	if err := json.Unmarshal(inner["id"], &id); err != nil {
		return ""
	}
	return id
}

// presentKeysAtPath returns the set of keys in the JSON object at top.<topField>.
// An absent or non-object value yields an empty set without error.
func presentKeysAtPath(jsonBytes []byte, topField string) (map[string]bool, error) {
	_, inner, err := nestedFieldRaw(jsonBytes, topField)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(inner))
	for k := range inner {
		out[k] = true
	}
	return out, nil
}

// unmarshalNested unmarshals the JSON value at top.<topField> into dst.
func unmarshalNested(jsonBytes []byte, topField string, dst proto.Message) error {
	raw, _, err := nestedFieldRaw(jsonBytes, topField)
	if err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("field %q not present", topField)
	}
	return protojson.Unmarshal(raw, dst)
}

// mergeFields produces a new message with the descriptor of incoming. For
// each field:
//   - sensitive fields are taken from existing (the LLM never had them);
//   - non-sensitive fields named in setKeys (by JSON name or proto name) are
//     overlaid from incoming;
//   - all other fields fall through from existing.
func mergeFields(
	existing, incoming protoreflect.Message,
	setKeys map[string]bool,
) protoreflect.Message {
	merged := proto.Clone(existing.Interface()).ProtoReflect()
	fields := incoming.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if IsSensitive(fd) {
			continue
		}
		if !setKeys[fd.JSONName()] && !setKeys[string(fd.Name())] {
			continue
		}
		if incoming.Has(fd) {
			merged.Set(fd, incoming.Get(fd))
		} else {
			merged.Clear(fd)
		}
	}
	return merged
}
