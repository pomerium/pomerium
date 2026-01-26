package protoutil

import (
	"bytes"
	"cmp"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A CompareFunc returns a function which compares two values similar to
// cmp.Compare.
type CompareFunc[T any] = func(x, y T) int

// CompareFuncForFieldMask returns a function which compares protobuf messages
// for the given fieldmask. If the fieldmask references invalid fields or types
// which aren't supported, an error will be returned.
func CompareFuncForFieldMask[T any, TMsg interface {
	*T
	proto.Message
}](m *fieldmaskpb.FieldMask) (CompareFunc[TMsg], error) {
	md := TMsg(new(T)).ProtoReflect().Descriptor()
	// for each field mask path, if when the messages are compared by the
	// field referenced by the path are equal, try with the next path
	fns := make([]CompareFunc[TMsg], len(m.Paths))
	for i, p := range m.Paths {
		var err error
		fns[i], err = compareFuncForPath[TMsg](md, p)
		if err != nil {
			return nil, err
		}
	}
	return combineCompareFuncs(fns...), nil
}

func combineCompareFuncs[T any](fns ...CompareFunc[T]) CompareFunc[T] {
	return func(x, y T) int {
		for _, fn := range fns {
			v := fn(x, y)
			if v != 0 {
				return v
			}
		}
		return 0
	}
}

func compareFuncForPath[TMsg proto.Message](md protoreflect.MessageDescriptor, path string) (CompareFunc[TMsg], error) {
	// first retrieve inner messages to support x.y.z style paths
	getMessage := func(msg proto.Message) proto.Message { return msg }
	segments := strings.Split(path, ".")
	for i := 0; i < len(segments)-1; i++ {
		segment := segments[i]
		fd := md.Fields().ByName(protoreflect.Name(segment))
		if fd == nil {
			return nil, fmt.Errorf("unknown protobuf field %s for %s", segment, md.FullName())
		}

		if fd.Cardinality() == protoreflect.Repeated {
			return nil, fmt.Errorf("repeated messages are not supported")
		}

		if fd.Kind() != protoreflect.MessageKind {
			return nil, fmt.Errorf("only messages are supported for field access")
		}

		prevGetMessage := getMessage
		getMessage = func(msg proto.Message) proto.Message {
			return prevGetMessage(msg).ProtoReflect().Get(fd).Message().Interface()
		}
		md = fd.Message()
	}
	// handle the last segment of the path by retrieving the field value and comparing that
	last := segments[len(segments)-1]
	fd := md.Fields().ByName(protoreflect.Name(last))
	if fd == nil {
		return nil, fmt.Errorf("unknown protobuf field %s for %s", last, md.FullName())
	}
	compare, err := compareFuncForField(fd)
	if err != nil {
		return nil, err
	}
	return func(x, y TMsg) int {
		return compare(getMessage(x), getMessage(y))
	}, nil
}

func compareFuncForField(fd protoreflect.FieldDescriptor) (CompareFunc[proto.Message], error) {
	if fd.IsMap() {
		return nil, fmt.Errorf("maps are not supported")
	}

	switch fd.Kind() {
	case protoreflect.BoolKind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) byte {
			// cmp.Compare doesn't support bools, so treat them like bytes instead
			if value.Bool() {
				return 1
			}
			return 0
		}, cmp.Compare), nil
	case protoreflect.EnumKind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) protoreflect.EnumNumber {
			return value.Enum()
		}, cmp.Compare), nil
	case protoreflect.Int32Kind,
		protoreflect.Sint32Kind,
		protoreflect.Int64Kind,
		protoreflect.Sint64Kind,
		protoreflect.Sfixed32Kind,
		protoreflect.Sfixed64Kind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) int64 {
			return value.Int()
		}, cmp.Compare), nil
	case protoreflect.Uint32Kind,
		protoreflect.Uint64Kind,
		protoreflect.Fixed32Kind,
		protoreflect.Fixed64Kind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) uint64 {
			return value.Uint()
		}, cmp.Compare), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) float64 {
			return value.Float()
		}, cmp.Compare), nil
	case protoreflect.StringKind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) string {
			return value.String()
		}, cmp.Compare), nil
	case protoreflect.BytesKind:
		return compareFuncForFieldGetter(fd, func(value protoreflect.Value) []byte {
			return value.Bytes()
		}, bytes.Compare), nil
	case protoreflect.MessageKind:
		fmd := fd.Message()
		switch fmd.FullName() {
		case "google.protobuf.Duration":
			return compareFuncForFieldGetter(fd, func(value protoreflect.Value) time.Duration {
				return value.Message().Interface().(*durationpb.Duration).AsDuration()
			}, cmp.Compare), nil
		case "google.protobuf.Timestamp":
			return compareFuncForFieldGetter(fd, func(value protoreflect.Value) time.Time {
				return value.Message().Interface().(*timestamppb.Timestamp).AsTime()
			}, func(x, y time.Time) int { return x.Compare(y) }), nil
		default:
			return compareFuncForFieldGetter(fd, func(value protoreflect.Value) []byte {
				bs, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(value.Message().Interface())
				return bs
			}, bytes.Compare), nil
		}
	case protoreflect.GroupKind:
		return nil, fmt.Errorf("groups are not supported")
	default:
		return nil, fmt.Errorf("unknown kind")
	}
}

func compareFuncForFieldGetter[T any](
	fd protoreflect.FieldDescriptor,
	getter func(msg protoreflect.Value) T,
	compare CompareFunc[T],
) CompareFunc[proto.Message] {
	// allow lists of values,
	// this is done by comparing all the values of the lists
	// lists containing identical prefixes will be ordered
	// such that the list with more elements occurs after
	// for example: 1: [a,a], 2: [a,a,a], 2 should occur
	// after 1
	if fd.IsList() {
		return func(x, y proto.Message) int {
			xl := x.ProtoReflect().Get(fd).List()
			xvs := make([]T, xl.Len())
			for i := range xl.Len() {
				xvs[i] = getter(xl.Get(i))
			}
			yl := y.ProtoReflect().Get(fd).List()
			yvs := make([]T, yl.Len())
			for i := range yl.Len() {
				yvs[i] = getter(yl.Get(i))
			}
			for i := 0; i < max(len(xvs), len(yvs)); i++ {
				if i >= len(xvs) {
					return 1
				} else if i >= len(yvs) {
					return -1
				}
				c := compare(xvs[i], yvs[i])
				if c != 0 {
					return c
				}
			}
			return 0
		}
	}

	// for scalar values, get the value and use the compare function directly
	return func(x, y proto.Message) int {
		xv := getter(x.ProtoReflect().Get(fd))
		yv := getter(y.ProtoReflect().Get(fd))
		return compare(xv, yv)
	}
}
