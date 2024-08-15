package protoutil

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// OverwriteMasked copies values from src to dst subject to a field mask. It
// will will return an error if dst and src are not the same type of message,
// or if some path in the field mask is not valid for that message type.
func OverwriteMasked(dst, src proto.Message, m *fieldmaskpb.FieldMask) error {
	return newFieldMaskTree(m).overwrite(dst.ProtoReflect(), src.ProtoReflect())
}

// fieldMaskTree represents a FieldMask as a tree, making it simpler to operate
// on messages recursively.
type fieldMaskTree map[string]fieldMaskTree

func newFieldMaskTree(m *fieldmaskpb.FieldMask) fieldMaskTree {
	var t fieldMaskTree
	for _, p := range m.GetPaths() {
		t.addFieldPath(p)
	}
	return t
}

// This is inspired by FieldMaskTree.java from the Java protobuf library:
// https://github.com/protocolbuffers/protobuf/blob/3667102d9/java/util/src/main/java/com/google/protobuf/util/FieldMaskTree.java#L76
func (t *fieldMaskTree) addFieldPath(path string) {
	if *t == nil {
		*t = make(map[string]fieldMaskTree)
	}

	parts := strings.Split(path, ".")

	node := *t
	for _, p := range parts {
		m := node[p]
		if m == nil {
			m = make(fieldMaskTree)
			node[p] = m
		} else if len(m) == 0 {
			return
		}
		node = m
	}
	clear(node)
}

// ErrDescriptorMismatch indicates an operation could not be performed because
// two proto messages did not have identical descriptors.
var ErrDescriptorMismatch = errors.New("descriptor mismatch")

func (t fieldMaskTree) overwrite(dst, src protoreflect.Message) error {
	dd, sd := dst.Descriptor(), src.Descriptor()
	if dd != sd {
		return fmt.Errorf("%w: %v, %v", ErrDescriptorMismatch, dd.FullName(), sd.FullName())
	}

	fields := dd.Fields()

	for p, subTree := range t {
		f := fields.ByName(protoreflect.Name(p))
		if f == nil {
			return fmt.Errorf("cannot overwrite unknown field %q in message %v", p, dd.FullName())
		}

		if len(subTree) > 0 {
			if f.Cardinality() == protoreflect.Repeated || f.Kind() != protoreflect.MessageKind {
				return fmt.Errorf("cannot overwrite sub-fields of field %q in message %v",
					f.TextName(), dd.FullName())
			}
			if !dst.Has(f) && !src.Has(f) {
				// no need to copy sub-fields of fields that aren't present in either message
				continue
			}
			err := subTree.overwrite(dst.Mutable(f).Message(), src.Get(f).Message())
			if err != nil {
				return err
			}
			continue
		}

		if src.Has(f) {
			dst.Set(f, src.Get(f))
		} else {
			dst.Clear(f)
		}
	}

	return nil
}
