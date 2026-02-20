package storage

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/slices"
)

const (
	indexField = "$index"
	cidrField  = "cidr"
)

var (
	ErrNoSuchIndex                = errors.New("no such index found")
	ErrIndexUnsupportedProtoField = errors.New("proto field is unsupported")
)

// GetRecordIndex gets a record's index. If there is no index, nil is returned.
func GetRecordIndex(msg proto.Message) *structpb.Struct {
	for {
		data, ok := msg.(*anypb.Any)
		if !ok {
			break
		}
		msg, _ = data.UnmarshalNew()
	}

	var s *structpb.Struct
	if sv, ok := msg.(*structpb.Value); ok {
		s = sv.GetStructValue()
	} else {
		s, _ = msg.(*structpb.Struct)
	}
	if s == nil {
		return nil
	}

	f, ok := s.Fields[indexField]
	if !ok {
		return nil
	}
	return f.GetStructValue()
}

func handleAny(val any) (string, error) {
	switch v := val.(type) {
	case string:
		return v, nil
	default:
		return "", fmt.Errorf("%T : %w", v, ErrIndexUnsupportedProtoField)
	}
}

func handleMap(in map[string]any, fieldTable map[string]string, fields []string) error {
	for _, key := range fields {
		parts := strings.Split(key, ".")
		cur := in
		for partIdx, part := range parts {
			val, ok := cur[part]
			if !ok {
				break
			}
			if partIdx == len(parts)-1 {
				indexVal, err := handleAny(val)
				if err != nil {
					return err
				}
				fieldTable[key] = indexVal
			} else {
				next, ok := val.(map[string]any)
				if !ok {
					break
				}
				cur = next
			}
		}
	}
	return nil
}

func GetIndexableFields(msg *anypb.Any, fields []string) (mappings map[string]string, err error) {
	fieldTable := slices.Associate(fields, func(field string) (string, string) {
		return field, ""
	})
	mapSt, err := anyToMap(msg)
	if err != nil {
		return nil, err
	}

	err = handleMap(mapSt, fieldTable, fields)
	return fieldTable, err
}

func fieldToValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch {
	case fd.IsList():
		l := v.List()
		res := make([]any, l.Len())
		for i := 0; i < l.Len(); i++ {
			res[i] = kindToValue(fd.Kind(), l.Get(i))
		}
		return res

	case fd.IsMap():
		m := v.Map()
		res := make(map[string]any)
		m.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
			res[k.String()] = kindToValue(fd.MapValue().Kind(), v)
			return true
		})
		return res
	}

	return kindToValue(fd.Kind(), v)
}

func kindToValue(kind protoreflect.Kind, v protoreflect.Value) any {
	switch kind {
	case protoreflect.BoolKind:
		return v.Bool()
	case protoreflect.StringKind:
		return v.String()
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return int32(v.Int())
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return v.Int()
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return uint32(v.Uint())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return v.Uint()
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return v.Float()
	case protoreflect.EnumKind:
		return v.Enum()
	case protoreflect.MessageKind:
		return MsgToMap(v.Message())
	default:
		panic("unhandled kind")
	}
}

func MsgToMap(m protoreflect.Message) map[string]any {
	out := make(map[string]any)
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		out[string(fd.Name())] = fieldToValue(fd, v)
		return true
	})
	return out
}

func anyToMap(a *anypb.Any) (map[string]any, error) {
	msg, err := a.UnmarshalNew()
	if err != nil {
		return nil, err
	}
	return MsgToMap(msg.ProtoReflect()), nil
}

// GetRecordIndexCIDR returns the $index.cidr for a record's data. If none is available nil is returned.
func GetRecordIndexCIDR(msg proto.Message) *netip.Prefix {
	obj := GetRecordIndex(msg)
	if obj == nil {
		return nil
	}

	cf, ok := obj.Fields[cidrField]
	if !ok {
		return nil
	}

	c := cf.GetStringValue()
	if c == "" {
		return nil
	}

	prefix, err := netip.ParsePrefix(c)
	if err != nil {
		return nil
	}
	return &prefix
}
