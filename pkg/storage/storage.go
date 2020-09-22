// Package storage provide generic interface to interact with storage backend.
package storage

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Backend is the interface required for a storage backend.
type Backend interface {
	// Close closes the backend.
	Close() error

	// Put is used to insert or update a record.
	Put(ctx context.Context, id string, data *anypb.Any) error

	// Get is used to retrieve a record.
	Get(ctx context.Context, id string) (*databroker.Record, error)

	// GetAll is used to retrieve all the records.
	GetAll(ctx context.Context) ([]*databroker.Record, error)

	// List is used to retrieve all the records since a version.
	List(ctx context.Context, sinceVersion string) ([]*databroker.Record, error)

	// Delete is used to mark a record as deleted.
	Delete(ctx context.Context, id string) error

	// ClearDeleted is used clear marked delete records.
	ClearDeleted(ctx context.Context, cutoff time.Time)

	// Query queries for records.
	Query(ctx context.Context, query string, offset, limit int) ([]*databroker.Record, int, error)

	// Watch returns a channel to the caller. The channel is used to notify
	// about changes that happen in storage. When ctx is finished, Watch will close
	// the channel.
	Watch(ctx context.Context) <-chan struct{}
}

// MatchAny searches any data with a query.
func MatchAny(any *anypb.Any, query string) bool {
	if any == nil {
		return false
	}

	msg, err := any.UnmarshalNew()
	if err != nil {
		// ignore invalid any types
		return false
	}

	// search by query
	return matchProtoMessage(msg.ProtoReflect(), query)
}

func matchProtoMessage(msg protoreflect.Message, query string) bool {
	matches := false

	md := msg.Descriptor()
	fds := md.Fields()
	for i := 0; i < fds.Len(); i++ {
		fd := fds.Get(i)
		if !msg.Has(fd) {
			continue
		}
		matches = matches || matchProtoValue(fd, msg.Get(fd), query)
	}

	return matches
}

func matchProtoValue(fd protoreflect.FieldDescriptor, v protoreflect.Value, query string) bool {
	switch {
	case fd.IsList():
		return matchProtoListValue(fd, v.List(), query)
	case fd.IsMap():
		return matchProtoMapValue(fd, v.Map(), query)
	default:
		return matchProtoSingularValue(fd, v, query)
	}
}

func matchProtoSingularValue(fd protoreflect.FieldDescriptor, v protoreflect.Value, query string) bool {
	switch fd.Kind() {
	case protoreflect.MessageKind:
		return matchProtoMessage(v.Message(), query)
	case protoreflect.StringKind:
		return strings.Contains(strings.ToLower(v.String()), query)
	}
	return false
}

func matchProtoListValue(fd protoreflect.FieldDescriptor, l protoreflect.List, query string) bool {
	matches := false
	for i := 0; i < l.Len(); i++ {
		matches = matches || matchProtoSingularValue(fd, l.Get(i), query)
	}
	return matches
}

func matchProtoMapValue(fd protoreflect.FieldDescriptor, m protoreflect.Map, query string) bool {
	matches := false
	m.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		matches = matches || matchProtoSingularValue(fd, v, query)
		return true
	})
	return matches
}
