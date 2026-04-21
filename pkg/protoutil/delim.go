package protoutil

import (
	"bufio"
	"bytes"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func MarshalLenghDelimitedProtojson[T proto.Message](msgs []T) ([]byte, error) {
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
		data, err := opts.Marshal(msg)
		if err != nil {
			return nil, err
		}
		buf = append(buf, data...)
		buf = append(buf, []byte("\n")...)
	}
	return buf, nil
}

func UnmarshalLengthDelimitedProtojson[T proto.Message](data []byte) ([]T, error) {
	s := bufio.NewScanner(bytes.NewReader(data))
	var msgs []T
	for s.Scan() {
		line := s.Bytes()
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
	var buf []byte
	for _, msg := range msgs {
		data, err := proto.Marshal(msg)
		if err != nil {
			return nil, err
		}
		buf = protowire.AppendVarint(buf, uint64(len(data)))
		buf = append(buf, data...)
	}
	return buf, nil
}

// UnmarshalLengthDelimited decodes a varint-length-delimited byte buffer into
// a slice of proto messages.
func UnmarshalLengthDelimited[T proto.Message](buf []byte) ([]T, error) {
	var msgs []T
	for len(buf) > 0 {
		size, n := protowire.ConsumeVarint(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid varint in length-delimited stream")
		}
		buf = buf[n:]
		if uint64(len(buf)) < size {
			return nil, fmt.Errorf("truncated message: need %d bytes, have %d", size, len(buf))
		}
		msg := newProtoMessage[T]()
		if err := proto.Unmarshal(buf[:size], msg); err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
		buf = buf[size:]
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
