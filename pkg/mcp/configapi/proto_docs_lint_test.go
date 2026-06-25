package configapi_test

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// undocumentedFieldAllowlist names fields whose leading-comment documentation
// in config.proto is intentionally missing. Keep this set small and only add
// an entry with an inline justification — the whole point of the
// accompanying lint is to keep every operator-facing field documented so
// MCP clients (and humans) can understand what each setting does.
//
// Map "Entry" messages (the synthetic types protoc generates for map fields)
// are excluded structurally; they should never appear here.
var undocumentedFieldAllowlist = map[string]string{}

// TestProtoFieldsAreDocumented fails when any field declared in config.proto
// lacks a leading-comment documentation block. The leading comment is what
// configapi (and protoc-gen-doc downstream) surfaces as the MCP "description"
// for every tool field — without it, an LLM caller sees only the field name
// and type, losing the operator-facing intent.
//
// The lint walks every message reachable from File_config_proto (including
// nested ones), skips synthetic map-entry messages, and consults the doc
// index built from config.pb.json. Any missing field that is not on the
// allowlist fails the test with its fully-qualified name so the contributor
// knows exactly which comment to add.
func TestProtoFieldsAreDocumented(t *testing.T) {
	t.Parallel()

	var missing []string
	visited := map[protoreflect.FullName]bool{}

	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if visited[md.FullName()] {
			return
		}
		visited[md.FullName()] = true

		// Synthetic key/value Entry messages have no human-facing semantics
		// beyond their parent map field, which IS subject to the lint.
		if !md.IsMapEntry() {
			fields := md.Fields()
			for i := range fields.Len() {
				fd := fields.Get(i)
				path := string(md.FullName()) + "." + string(fd.Name())
				if v, ok := undocumentedFieldAllowlist[path]; ok && v != "" {
					continue
				}
				if configpb.FieldDescription(fd) == "" {
					missing = append(missing, path)
				}
			}
		}

		nested := md.Messages()
		for i := range nested.Len() {
			walk(nested.Get(i))
		}
	}

	msgs := configpb.File_config_proto.Messages()
	for i := range msgs.Len() {
		walk(msgs.Get(i))
	}

	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)
	t.Fatalf(
		"the following config.proto fields are missing a leading-comment "+
			"description. Add a // comment immediately above each field so "+
			"the MCP tool schema (and protoc-gen-doc output) carries it:\n  - %s",
		strings.Join(missing, "\n  - "),
	)
}

// zeroEnumValuePattern matches the protobuf-convention "unset" enum value
// (the one assigned number 0). These carry no semantics beyond "no value"
// and the lint does not require a leading comment for them.
var zeroEnumValueSuffixes = []string{
	"_UNSPECIFIED",
	"_UNKNOWN",
	"UNKNOWN", // some enums use a bare "UNKNOWN" zero value
}

// TestProtoEnumsAreDocumented fails when any enum or non-zero enum value
// declared in config.proto lacks a leading-comment description. configapi's
// enumSchema appends per-value docs to the JSON Schema description so an LLM
// choosing among values knows what each one does — an undocumented enum
// drops back to "(enum <FullName>) Values: …".
//
// The zero value of every enum (UNSPECIFIED/UNKNOWN/etc.) is exempt — by
// protobuf convention it means "field not set" and has no semantics of its
// own.
func TestProtoEnumsAreDocumented(t *testing.T) {
	t.Parallel()

	var missingEnums []string
	var missingValues []string
	visited := map[protoreflect.FullName]bool{}

	checkEnums := func(eds protoreflect.EnumDescriptors) {
		for i := range eds.Len() {
			ed := eds.Get(i)
			if configpb.EnumDescription(ed) == "" {
				missingEnums = append(missingEnums, string(ed.FullName()))
			}
			values := ed.Values()
			for j := range values.Len() {
				v := values.Get(j)
				if v.Number() == 0 || isExemptZeroName(string(v.Name())) {
					continue
				}
				if configpb.EnumValueDescription(v) == "" {
					missingValues = append(missingValues,
						string(ed.FullName())+"."+string(v.Name()))
				}
			}
		}
	}

	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if visited[md.FullName()] {
			return
		}
		visited[md.FullName()] = true
		checkEnums(md.Enums())
		nested := md.Messages()
		for i := range nested.Len() {
			walk(nested.Get(i))
		}
	}

	checkEnums(configpb.File_config_proto.Enums())
	msgs := configpb.File_config_proto.Messages()
	for i := range msgs.Len() {
		walk(msgs.Get(i))
	}

	if len(missingEnums) == 0 && len(missingValues) == 0 {
		return
	}
	sort.Strings(missingEnums)
	sort.Strings(missingValues)
	var sb strings.Builder
	if len(missingEnums) > 0 {
		sb.WriteString("enums missing a leading-comment description:\n  - ")
		sb.WriteString(strings.Join(missingEnums, "\n  - "))
		sb.WriteString("\n")
	}
	if len(missingValues) > 0 {
		sb.WriteString("enum values missing a leading-comment description " +
			"(zero values are exempt):\n  - ")
		sb.WriteString(strings.Join(missingValues, "\n  - "))
	}
	t.Fatal(sb.String())
}

func isExemptZeroName(name string) bool {
	for _, suffix := range zeroEnumValueSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
