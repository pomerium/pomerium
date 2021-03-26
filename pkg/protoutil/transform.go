package protoutil

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

// TransformFunc is a function that transforms a protobuf value into a new protobuf value.
type TransformFunc func(protoreflect.FieldDescriptor, protoreflect.Value) (protoreflect.Value, error)

// Transform takes in a protobuf message and transforms any basic values with the given function.
func Transform(msg proto.Message, f TransformFunc) (proto.Message, error) {
	t := transformer{callback: f}
	src := msg.ProtoReflect()
	dst := src.New()
	err := t.transformMessage(dst, src)
	if err != nil {
		return nil, err
	}
	return dst.Interface(), nil
}

type transformer struct {
	callback TransformFunc
}

func (t transformer) transformAny(dst, src *anypb.Any) error {
	msg, err := src.UnmarshalNew()
	if err != nil {
		return err
	}

	srcMsg := msg.ProtoReflect()
	dstMsg := srcMsg.New()

	err = t.transformMessage(dstMsg, srcMsg)
	if err != nil {
		return err
	}

	a, err := anypb.New(dstMsg.Interface())
	if err != nil {
		return err
	}
	dst.TypeUrl = a.TypeUrl
	dst.Value = a.Value
	return nil
}

func (t transformer) transformList(fd protoreflect.FieldDescriptor, dst, src protoreflect.List) error {
	for i, n := 0, src.Len(); i < n; i++ {
		v := src.Get(i)
		switch vv := v.Interface().(type) {
		case protoreflect.Message:
			nv := dst.NewElement()
			err := t.transformMessage(nv.Message(), vv)
			if err != nil {
				return err
			}
			dst.Append(nv)
		default:
			nv, err := t.callback(fd, v)
			if err != nil {
				return err
			}
			dst.Append(nv)
		}
	}
	return nil
}

func (t transformer) transformMap(fd protoreflect.FieldDescriptor, dst, src protoreflect.Map) error {
	var err error
	src.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		switch vv := v.Interface().(type) {
		case protoreflect.Message:
			nv := dst.NewValue()
			err := t.transformMessage(nv.Message(), vv)
			if err != nil {
				return false
			}
			dst.Set(k, nv)
		default:
			nv, err := t.callback(fd, v)
			if err != nil {
				return false
			}
			dst.Set(k, nv)
		}
		return true
	})
	return err
}

func (t transformer) transformMessage(dst, src protoreflect.Message) error {
	// most of this code is based on
	// https://github.com/protocolbuffers/protobuf-go/blob/v1.25.0/proto/merge.go
	if srcAny, ok := src.Interface().(*anypb.Any); ok {
		if dstAny, ok := dst.Interface().(*anypb.Any); ok {
			return t.transformAny(dstAny, srcAny)
		}
	}

	var err error
	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			err = t.transformList(fd, dst.Mutable(fd).List(), v.List())
			if err != nil {
				return false
			}
		case fd.IsMap():
			err = t.transformMap(fd, dst.Mutable(fd).Map(), v.Map())
			if err != nil {
				return false
			}
		case fd.Message() != nil:
			err = t.transformMessage(dst.Mutable(fd).Message(), v.Message())
			if err != nil {
				return false
			}
		default:
			var nv protoreflect.Value
			nv, err = t.callback(fd, v)
			if err != nil {
				return false
			}
			dst.Set(fd, nv)
		}
		return true
	})
	if err != nil {
		return err
	}

	if len(src.GetUnknown()) > 0 {
		dst.SetUnknown(append(dst.GetUnknown(), src.GetUnknown()...))
	}
	return nil
}
