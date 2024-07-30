package paths

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
)

func Parse(root protoreflect.MessageDescriptor, pathStr string) (protopath.Path, error) {
	if len(pathStr) == 0 {
		return nil, errors.New("empty path")
	}
	if pathStr[0] != '.' {
		return nil, errors.New("path must start with '.' (root step is omitted)")
	}
	pathStr = pathStr[1:]

	result := protopath.Path{protopath.Root(root)}

	// TODO(go1.23): replace with `for _, part := range parts {`
	doIter := func(part string) (any, error) {
		currentStep := result.Index(-1)
		if len(part) == 0 {
			return nil, errors.New("path contains empty step")
		}
		switch {
		case part[0] == '(' && part[len(part)-1] == ')':
			// AnyExpand
			var fd protoreflect.FieldDescriptor
			switch currentStep.Kind() {
			case protopath.FieldAccessStep:
				// someAnyField.(pkg.Type)
				fd = currentStep.FieldDescriptor()
			case protopath.ListIndexStep:
				// someRepeatedAnyField[index].(pkg.Type)
				fd = result.Index(-2).FieldDescriptor()
			case protopath.MapIndexStep:
				// someRepeatedAnyField["key"].(pkg.Type)
				fd = result.Index(-2).FieldDescriptor().MapValue()
			}
			if fd != nil {
				if fd.Kind() != protoreflect.MessageKind ||
					(fd.IsList() && currentStep.Kind() != protopath.ListIndexStep) ||
					(fd.IsMap() && currentStep.Kind() != protopath.MapIndexStep) ||
					fd.Message().FullName() != "google.protobuf.Any" {
					// envoy doesn't have any proto2 extensions, and we don't need to reference options
					return nil, fmt.Errorf("can only expand fields of type google.protobuf.Any, not %s", kindStr(fd))
				}
			} else if currentStep.Kind() != protopath.AnyExpandStep {
				return nil, fmt.Errorf("unexpected type expansion after %s step", currentStep.Kind())
			}

			msgName := protoreflect.FullName(part[1 : len(part)-1])
			if !msgName.IsValid() {
				if part[1] == '.' {
					return nil, fmt.Errorf("invalid message type '%s' (try removing the leading dot)", part[1:len(part)-1])
				}
				return nil, fmt.Errorf("invalid message type '%s'", part[1:len(part)-1])
			}
			if msgt, err := protoregistry.GlobalTypes.FindMessageByName(msgName); err != nil {
				if errors.Is(err, protoregistry.NotFound) {
					return nil, fmt.Errorf("message type %s not found", msgName)
				}
				return nil, fmt.Errorf("error looking up message type %s: %w", msgName, err)
			} else {
				result = append(result, protopath.AnyExpand(msgt.Descriptor()))
			}
		case part[0] == '[' && part[len(part)-1] == ']':
			// either ListIndex or MapIndex
			switch currentStep.Kind() {
			case protopath.FieldAccessStep:
				fd := currentStep.FieldDescriptor()
				if fd.IsList() {
					idx, err := strconv.ParseInt(part[1:len(part)-1], 10, 32)
					if err != nil {
						return nil, fmt.Errorf("invalid list index: %w", err)
					}
					result = append(result, protopath.ListIndex(int(idx)))
				} else if fd.IsMap() {
					key := part[1 : len(part)-1]
					switch fd.MapKey().Kind() {
					case protoreflect.StringKind:
						if len(key) == 0 {
							return nil, errors.New("empty map key")
						}
						unquoted, err := strconv.Unquote(key)
						if err != nil {
							return nil, fmt.Errorf("invalid string map key '%s': %w", key, err)
						}
						result = append(result, protopath.MapIndex(protoreflect.ValueOfString(unquoted).MapKey()))
					case protoreflect.BoolKind:
						switch key {
						case "true":
							result = append(result, protopath.MapIndex(protoreflect.ValueOfBool(true).MapKey()))
						case "false":
							result = append(result, protopath.MapIndex(protoreflect.ValueOfBool(false).MapKey()))
						default:
							return nil, fmt.Errorf("invalid map key '%s' for bool field '%s'", key, fd.FullName())
						}
					case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
						idx, err := strconv.ParseInt(key, 10, 32)
						if err != nil {
							return nil, fmt.Errorf("invalid map key '%s': %w", key, err)
						}
						result = append(result, protopath.MapIndex(protoreflect.ValueOfInt32(int32(idx)).MapKey()))
					case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
						idx, err := strconv.ParseInt(key, 10, 64)
						if err != nil {
							return nil, fmt.Errorf("invalid map key '%s': %w", key, err)
						}
						result = append(result, protopath.MapIndex(protoreflect.ValueOfInt64(idx).MapKey()))
					case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
						idx, err := strconv.ParseUint(key, 10, 32)
						if err != nil {
							return nil, fmt.Errorf("invalid map key '%s': %w", key, err)
						}
						result = append(result, protopath.MapIndex(protoreflect.ValueOfUint32(uint32(idx)).MapKey()))
					case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
						idx, err := strconv.ParseUint(key, 10, 64)
						if err != nil {
							return nil, fmt.Errorf("invalid map key '%s': %w", key, err)
						}
						result = append(result, protopath.MapIndex(protoreflect.ValueOfUint64(idx).MapKey()))
					}
				} else {
					return nil, fmt.Errorf("cannot index %s field '%s'", fd.Kind().String(), fd.FullName())
				}
			default:
				return nil, fmt.Errorf("cannot index '%s'", currentStep.String())
			}
		case part[0] == '?' && len(part) == 1:
			// UnknownAccess
			return nil, fmt.Errorf("unknown field access not supported")
		default:
			// FieldAccess
			var msg protoreflect.MessageDescriptor
			switch currentStep.Kind() {
			case protopath.RootStep, protopath.AnyExpandStep:
				msg = currentStep.MessageDescriptor()
			case protopath.FieldAccessStep:
				fd := currentStep.FieldDescriptor()
				if fd.Kind() == protoreflect.MessageKind {
					msg = fd.Message()
				}
			case protopath.ListIndexStep:
				prev := result.Index(-2)
				switch prev.Kind() {
				case protopath.FieldAccessStep:
					fd := prev.FieldDescriptor()
					if fd.Kind() == protoreflect.MessageKind {
						msg = fd.Message()
					}
				}
			case protopath.MapIndexStep:
				prev := result.Index(-2)
				switch prev.Kind() {
				case protopath.FieldAccessStep:
					fd := prev.FieldDescriptor()
					if fd.MapValue().Kind() == protoreflect.MessageKind {
						msg = fd.MapValue().Message()
					}
				}
			}
			if msg != nil {
				field := msg.Fields().ByName(protoreflect.Name(part))
				if field == nil {
					if msg.FullName() == "google.protobuf.Any" {
						return nil, fmt.Errorf("no such field '%s' in message %s (missing type expansion?)", part, msg.FullName())
					}
					return nil, fmt.Errorf("no such field '%s' in message %s", part, msg.FullName())
				}
				result = append(result, protopath.FieldAccess(field))
			} else {
				return nil, fmt.Errorf("cannot access field '%s' of non-message type", part)
			}
		}
		return nil, nil
	}
	var err error
	Split(pathStr)(func(part string) bool {
		_, err = doIter(part)
		return err == nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func kindStr(fd protoreflect.FieldDescriptor) string {
	switch fd.Kind() {
	case protoreflect.MessageKind:
		if fd.IsList() {
			return fmt.Sprintf("repeated %s", fd.Message().FullName())
		} else if fd.IsMap() {
			return fmt.Sprintf("map<%s, %s>", fd.MapKey().Kind().String(), kindStr(fd.MapValue()))
		}
		return string(fd.Message().FullName())
	default:
		return fd.Kind().String()
	}
}

// splits a path by '.' or '[' except within parentheses or quotes
func Split(pathStr string) func(yield func(string) bool) {
	pathStr = strings.TrimSpace(pathStr)
	return func(yield func(string) bool) {
		start := 0
		var withinParens bool
		var withinString rune
		for i, rn := range pathStr {
			switch rn {
			case '(':
				withinParens = true
			case ')':
				withinParens = false
			case '"', '\'':
				switch withinString {
				case rn:
					withinString = 0
				case 0:
					withinString = rn
				}
			case '.':
				if withinParens || withinString != 0 {
					continue
				}
				if !yield(pathStr[start:i]) {
					return
				}
				start = i + 1
			case '[':
				if withinParens || withinString != 0 {
					continue
				}
				if i-start > 0 {
					if !yield(pathStr[start:i]) {
						return
					}
					start = i
				}
			}
		}
		if len(pathStr)-start > 1 {
			yield(pathStr[start:])
		}
	}
}

func Dereference(root proto.Message, path protopath.Path) (protoreflect.Value, error) {
	v := protoreflect.ValueOfMessage(root.ProtoReflect())
	for _, step := range path {
		if !v.IsValid() {
			return protoreflect.Value{}, nil
		}
		switch step.Kind() {
		case protopath.FieldAccessStep:
			m := v.Message()
			if !m.IsValid() {
				return protoreflect.Value{}, nil
			}
			// check that the field descriptors match, otherwise this will panic
			if m.Descriptor() != step.FieldDescriptor().ContainingMessage() {
				expecting := m.Descriptor().FullName()
				have := step.FieldDescriptor().ContainingMessage().FullName()
				return protoreflect.Value{}, fmt.Errorf("cannot access field '%s': wrong message type: expecting %v, have %v", step.FieldDescriptor().FullName(), expecting, have)
			}
			v = m.Get(step.FieldDescriptor())
		case protopath.ListIndexStep:
			list := v.List()
			if !list.IsValid() {
				return protoreflect.Value{}, nil
			}
			v = list.Get(step.ListIndex())
		case protopath.MapIndexStep:
			m := v.Map()
			if !m.IsValid() {
				return protoreflect.Value{}, nil
			}
			v = m.Get(step.MapIndex())
		case protopath.AnyExpandStep:
			m := v.Message()
			if !m.IsValid() {
				return protoreflect.Value{}, nil
			}
			msg, err := m.Interface().(*anypb.Any).UnmarshalNew()
			if err != nil {
				panic(fmt.Errorf("bug: %w", err))
			}
			v = protoreflect.ValueOfMessage(msg.ProtoReflect())
		case protopath.RootStep:
			if v.Message().Descriptor() != step.MessageDescriptor() {
				panic(fmt.Sprintf("bug: mismatched root descriptor (%s != %s)",
					v.Message().Descriptor().FullName(), step.MessageDescriptor().FullName()))
			}
		}
	}
	return v, nil
}
