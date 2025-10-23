package storage

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
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

func GetForeignKeys(msg proto.Message, repeatedFields []string) (keys []string, err error) {
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
		return nil, ErrNoSuchIndex
	}
	keys = make([]string, len(repeatedFields))
	for idx, key := range repeatedFields {
		parts := strings.Split(key, ".")
		st := s
		for partIdx, part := range parts {
			val, ok := st.Fields[part]
			if !ok {
				return nil, fmt.Errorf("field '%s' : %w", part, ErrNoSuchIndex)
			}
			if partIdx == len(parts)-1 {
				indexVal, err := handleValue(val)
				if err != nil {
					return nil, err
				}
				keys[idx] = indexVal
			} else {
				if stv := val.GetStructValue(); stv == nil {
					return nil, fmt.Errorf("nested field %s : %w", part, ErrNoSuchIndex)
				} else {
					st = stv
				}
			}
		}
	}
	return
}

func handleValue(val *structpb.Value) (string, error) {
	switch v := val.GetKind().(type) {
	case *structpb.Value_StringValue:
		return val.GetStringValue(), nil
	default:
		return "", fmt.Errorf("%T : %w", v, ErrIndexUnsupportedProtoField)
	}
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
