package file

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
)

const keyDelimiter byte = 0x00

var (
	marshalOptions = proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	}
	unmarshalOptions = proto.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}
)

func decodeJoinedKey(data []byte, expectedPrefix byte, fieldCount int) ([][]byte, error) {
	if !bytes.HasPrefix(data, []byte{expectedPrefix}) {
		return nil, fmt.Errorf("unexpected key prefix")
	}

	segments := bytes.SplitN(data[1:], []byte{keyDelimiter}, fieldCount)
	if len(segments) != fieldCount {
		return nil, fmt.Errorf("unexpected key field count: %d", len(segments))
	}
	return segments, nil
}

func decodeProto[T any, TPtr interface {
	*T
	proto.Message
}](data []byte) (TPtr, error) {
	var msg T
	err := unmarshalOptions.Unmarshal(data, TPtr(&msg))
	if err != nil {
		return nil, err
	}
	return TPtr(&msg), nil
}

func decodeTimestamp(data []byte) (time.Time, error) {
	ts, err := decodeUint64(data)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp, %w", err)
	}
	return time.UnixMicro(int64(ts)).UTC(), nil
}

func decodeUint64(data []byte) (uint64, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("invalid uint64, expected 8 bytes, got %d", len(data))
	}
	return binary.BigEndian.Uint64(data), nil
}

func encodeProto(msg proto.Message) []byte {
	data, err := marshalOptions.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return data
}

func encodeJoinedKey(prefix byte, segments ...[]byte) []byte {
	sz := 1
	for i, segment := range segments {
		if i > 0 {
			sz++
		}
		sz += len(segment)
	}

	data := make([]byte, 0, sz)
	data = append(data, prefix)
	for i, segment := range segments {
		if i > 0 {
			data = append(data, keyDelimiter)
		}
		data = append(data, segment...)
	}

	return data
}

func encodeSimpleKey(prefix byte, key []byte) []byte {
	data := make([]byte, 0, 1+len(key))
	data = append(data, prefix)
	data = append(data, key...)
	return data
}

func encodeTimestamp(value time.Time) []byte {
	return encodeUint64(uint64(value.UTC().UnixMicro()))
}

func encodeUint64(value uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, value)
	return data
}

type leaseValue struct {
	id        string
	expiresAt time.Time
}

func decodeLeaseValue(data []byte) (leaseValue, error) {
	segments := bytes.SplitN(data, []byte{keyDelimiter}, 2)
	if len(segments) != 2 {
		return leaseValue{}, fmt.Errorf("expected lease id and timestamp")
	}

	value := leaseValue{id: string(segments[0])}
	var err error
	value.expiresAt, err = decodeTimestamp(segments[1])
	if err != nil {
		return leaseValue{}, fmt.Errorf("invalid lease expires at: %w", err)
	}
	return value, nil
}

func encodeLeaseValue(value leaseValue) []byte {
	return bytes.Join([][]byte{
		[]byte(value.id),
		encodeTimestamp(value.expiresAt),
	}, []byte{keyDelimiter})
}
