package configapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
// perCallHeaders are forwarded to the inner Get call so any PreCall-derived
// scope (e.g. cluster id) targets the same record that the outer Update
// will modify; without this the Get could land in a different scope and
// the merged write would silently corrupt an unrelated entity.
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
	perCallHeaders http.Header,
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
	getRespJSON, err := caller.call(ctx, getMethod, getReqJSON, perCallHeaders)
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

	keyTree, err := jsonKeyTreeAtPath(inputJSON, entityField.JSONName())
	if err != nil {
		return inputJSON, false, fmt.Errorf("inspecting incoming JSON keys: %w", err)
	}

	merged := mergeFields(existingEntity, incomingEntity, keyTree)

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

// jsonKeyNode mirrors the shape of a JSON object: leaf entries map to nil,
// nested objects map to a child node. Tracking presence at every depth lets
// the merge distinguish "the LLM included this key" from "the LLM didn't
// touch this object" — including the explicit-clear case where the LLM sets
// a leaf to its zero value (empty string, false, []).
type jsonKeyNode map[string]*jsonKeyNode

// jsonKeyTreeAtPath returns the JSON-key tree for the object at top.<topField>.
// An absent or non-object value yields nil without error.
func jsonKeyTreeAtPath(jsonBytes []byte, topField string) (jsonKeyNode, error) {
	_, inner, err := nestedFieldRaw(jsonBytes, topField)
	if err != nil {
		return nil, err
	}
	return buildKeyTree(inner), nil
}

func buildKeyTree(inner map[string]json.RawMessage) jsonKeyNode {
	if inner == nil {
		return nil
	}
	out := make(jsonKeyNode, len(inner))
	for k, v := range inner {
		if !isJSONObject(v) {
			out[k] = nil
			continue
		}
		var sub map[string]json.RawMessage
		if err := json.Unmarshal(v, &sub); err != nil {
			out[k] = nil
			continue
		}
		child := buildKeyTree(sub)
		out[k] = &child
	}
	return out
}

// isJSONObject reports whether raw is a JSON object value, by peeking past
// any leading whitespace at its first significant byte. Avoids re-parsing
// every value just to ask "is this an object?".
func isJSONObject(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
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

// mergeFields returns a clone of existing with non-sensitive fields the LLM
// included in keyTree overlaid from incoming. The merge recurses into
// non-sensitive singular message fields so deeply-nested sensitive scalars
// survive an update that touches any of their non-sensitive ancestors. Per
// field:
//
//   - sensitive fields (at any depth) are taken from existing — the LLM never
//     had their values, so it cannot supply them on Update;
//   - non-sensitive fields whose JSON-name (or proto name) appears in keyTree
//     are overlaid from incoming. For singular message fields with an object
//     subtree in keyTree, the merge recurses against the existing sub-message;
//   - all other fields fall through from existing.
//
// keyTree is the JSON object the LLM sent at this level (see jsonKeyTreeAtPath).
// Tracking it explicitly — rather than deriving "is this field set?" from the
// parsed proto — preserves explicit-clear semantics for proto3 non-optional
// scalars at any depth, since for those Has() == false even when the LLM
// included the field with its zero value.
//
// Lists and maps of messages are replaced wholesale; per-element merge would
// require an entity identity rule the proto doesn't carry. List/map fields
// whose element type contains nested sensitive fields are therefore unsafe to
// expose for sparse update, and should be skipped from the auto-tool schema.
func mergeFields(
	existing, incoming protoreflect.Message,
	keyTree jsonKeyNode,
) protoreflect.Message {
	merged := proto.Clone(existing.Interface()).ProtoReflect()
	mergeInto(merged, incoming, keyTree)
	return merged
}

// mergeInto applies the incoming overlay to merged in-place. merged starts as
// a clone of the existing record (see mergeFields); the recursion mutates its
// sub-messages directly via Mutable so we don't re-clone whole subtrees at
// each depth.
func mergeInto(merged, incoming protoreflect.Message, keyTree jsonKeyNode) {
	fields := incoming.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if IsSensitive(fd) {
			continue
		}
		sub, present := lookupKey(keyTree, fd)
		if !present {
			continue
		}
		if !incoming.Has(fd) {
			merged.Clear(fd)
			continue
		}
		if sub != nil && fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() {
			mergeInto(merged.Mutable(fd).Message(), incoming.Get(fd).Message(), *sub)
			continue
		}
		merged.Set(fd, incoming.Get(fd))
	}
}

// lookupKey resolves a field descriptor against a JSON key tree, accepting
// either the protojson camelCase name or the proto snake_case name. Returns
// the subtree (nil for scalar leaves) and whether the key was present.
func lookupKey(tree jsonKeyNode, fd protoreflect.FieldDescriptor) (*jsonKeyNode, bool) {
	if tree == nil {
		return nil, false
	}
	if v, ok := tree[fd.JSONName()]; ok {
		return v, true
	}
	if v, ok := tree[string(fd.Name())]; ok {
		return v, true
	}
	return nil, false
}
