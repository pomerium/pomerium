package protoutil

import (
	"bytes"
	"reflect"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func MarshalNewLineDelimitedProtoJSON[T proto.Message](msgs []T) ([]byte, error) {
	var buf []byte
	opts := protojson.MarshalOptions{
		Multiline:         false,
		Indent:            "",
		AllowPartial:      false,
		UseProtoNames:     true,
		UseEnumNumbers:    false,
		EmitUnpopulated:   true,
		EmitDefaultValues: true,
	}
	for _, msg := range msgs {
		var err error
		buf, err = opts.MarshalAppend(buf, msg)
		if err != nil {
			return nil, err
		}
		buf = append(buf, '\n')
	}
	return buf, nil
}

func UnmarshalNewLineDelimitedProtoJSON[T proto.Message](data []byte) ([]T, error) {
	var msgs []T
	for len(data) > 0 {
		var line []byte
		if before, after, ok := bytes.Cut(data, []byte{'\n'}); ok {
			line, data = before, after
		} else {
			line, data = data, nil
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		msg := newProtoMessage[T]()
		if err := protojson.Unmarshal(line, msg); err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

// MarshalLengthDelimited encodes a slice of proto messages into a single byte
// buffer using varint-length-delimited framing.
func MarshalLengthDelimited[T proto.Message](msgs []T) ([]byte, error) {
	var w bytes.Buffer
	for _, msg := range msgs {
		if _, err := protodelim.MarshalTo(&w, msg); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

// UnmarshalLengthDelimited decodes a varint-length-delimited byte buffer into
// a slice of proto messages.
func UnmarshalLengthDelimited[T proto.Message](buf []byte) ([]T, error) {
	var msgs []T
	r := bytes.NewReader(buf)
	for r.Len() > 0 {
		msg := newProtoMessage[T]()
		if err := protodelim.UnmarshalFrom(r, msg); err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func newProtoMessage[T proto.Message]() T {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface().(T)
	}
	return zero
}
