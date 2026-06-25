package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"
)

//go:embed config.pb.json
var protoDocJSON []byte

// docPayload mirrors the subset of protoc-gen-doc's JSON output we need to
// recover leading comments for messages, fields, and enum values. The full
// schema carries many other keys (defaults, label, oneof bookkeeping); we
// ignore them.
type docPayload struct {
	Files []struct {
		Messages []docMessage `json:"messages"`
		Enums    []docEnum    `json:"enums"`
	} `json:"files"`
}

type docMessage struct {
	FullName    string     `json:"fullName"`
	Description string     `json:"description"`
	Fields      []docField `json:"fields"`
}

type docField struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type docEnum struct {
	FullName    string         `json:"fullName"`
	Description string         `json:"description"`
	Values      []docEnumValue `json:"values"`
}

type docEnumValue struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// descIndex is the parsed lookup built once at first use.
type descIndex struct {
	// message FullName -> description.
	messages map[string]string
	// message FullName + "." + field Name -> description.
	fields map[string]string
	// enum FullName -> description.
	enums map[string]string
	// enum FullName + "." + value Name -> description.
	enumValues map[string]string
}

var (
	descOnce  sync.Once
	descCache *descIndex
)

func loadDescriptions() *descIndex {
	descOnce.Do(func() {
		var p docPayload
		if err := json.Unmarshal(protoDocJSON, &p); err != nil {
			// protoDocJSON is embedded at compile time from
			// config.pb.json; an unmarshal error means the generator
			// emitted output we can't read. That's a build-time bug —
			// fail loudly rather than silently strip every description.
			panic(fmt.Errorf("configpb: parsing embedded config.pb.json: %w", err))
		}
		idx := &descIndex{
			messages:   map[string]string{},
			fields:     map[string]string{},
			enums:      map[string]string{},
			enumValues: map[string]string{},
		}
		for _, f := range p.Files {
			for _, m := range f.Messages {
				if d := normalize(m.Description); d != "" {
					idx.messages[m.FullName] = d
				}
				for _, fld := range m.Fields {
					if d := normalize(fld.Description); d != "" {
						idx.fields[m.FullName+"."+fld.Name] = d
					}
				}
			}
			for _, e := range f.Enums {
				if d := normalize(e.Description); d != "" {
					idx.enums[e.FullName] = d
				}
				for _, v := range e.Values {
					if d := normalize(v.Description); d != "" {
						idx.enumValues[e.FullName+"."+v.Name] = d
					}
				}
			}
		}
		descCache = idx
	})
	return descCache
}

// protoc-gen-doc preserves leading-comment newlines verbatim; collapse them
// to single spaces so the strings are usable as JSON Schema "description"
// values (which LLM clients render as paragraphs). Trim surrounding space.
func normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Normalize line endings, then collapse internal whitespace runs to one
	// space. Multi-line comments in the .proto become single-line summaries.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// FieldDescription returns the leading-comment documentation for a protobuf
// field, or "" if the field has no comment in config.proto.
func FieldDescription(fd protoreflect.FieldDescriptor) string {
	if fd == nil {
		return ""
	}
	parent := fd.Parent()
	if parent == nil {
		return ""
	}
	return loadDescriptions().fields[string(parent.FullName())+"."+string(fd.Name())]
}

// MessageDescription returns the leading-comment documentation for a protobuf
// message, or "" if the message has no comment in config.proto.
func MessageDescription(md protoreflect.MessageDescriptor) string {
	if md == nil {
		return ""
	}
	return loadDescriptions().messages[string(md.FullName())]
}

// EnumDescription returns the leading-comment documentation for a protobuf
// enum, or "" if the enum has no comment in config.proto.
func EnumDescription(ed protoreflect.EnumDescriptor) string {
	if ed == nil {
		return ""
	}
	return loadDescriptions().enums[string(ed.FullName())]
}

// EnumValueDescription returns the leading-comment documentation for an enum
// value, or "" if the value has no comment in config.proto.
func EnumValueDescription(ev protoreflect.EnumValueDescriptor) string {
	if ev == nil {
		return ""
	}
	parent := ev.Parent()
	if parent == nil {
		return ""
	}
	return loadDescriptions().enumValues[string(parent.FullName())+"."+string(ev.Name())]
}
