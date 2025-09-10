// Package storage provide generic interface to interact with storage backend.
package storage

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Errors
var (
	ErrNotFound             = status.Error(codes.NotFound, "record not found")
	ErrStreamDone           = errors.New("record stream done")
	ErrInvalidServerVersion = status.Error(codes.Aborted, "invalid server version")
	ErrInvalidRecordVersion = status.Error(codes.Aborted, "invalid record version")
)

// Versions are the server and record versions for the storage backend.
type Versions struct {
	// ServerVersion uniquely identifies a storage backend instance.
	ServerVersion uint64
	// EarliestRecordVersion is the earliest record version that the storage
	// backend has stored.
	EarliestRecordVersion uint64
	// LatestRecordVersion is the latest record version that the storage
	// backend has stored.
	LatestRecordVersion uint64

	// LeaderServerVersion is the server version of the leader,
	// used when clustered.
	LeaderServerVersion uint64
	// LeaderLatestRecordVersion is the latest record version of the leader,
	// used when clustered.
	LeaderLatestRecordVersion uint64
}

// Backend is the interface required for a storage backend.
type Backend interface {
	// Close closes the backend.
	Close() error
	// Clean removes old data.
	Clean(ctx context.Context, options CleanOptions) error
	// Clear removes all records from the storage backend.
	Clear(ctx context.Context) error
	// Get is used to retrieve a record.
	Get(ctx context.Context, recordType, id string) (*databroker.Record, error)
	// GetCheckpoint gets the latest checkpoint.
	GetCheckpoint(ctx context.Context) (serverVersion, recordVersion uint64, err error)
	// GetOptions gets the options for a type.
	GetOptions(ctx context.Context, recordType string) (*databroker.Options, error)
	// Lease acquires a lease, or renews an existing one. If the lease is acquired true is returned.
	Lease(ctx context.Context, leaseName, leaseID string, ttl time.Duration) (bool, error)
	// ListTypes lists all the known record types.
	ListTypes(ctx context.Context) ([]string, error)
	// Put is used to insert or update records.
	Put(ctx context.Context, records []*databroker.Record) (serverVersion uint64, err error)
	// Patch is used to update specific fields of existing records.
	Patch(ctx context.Context, records []*databroker.Record, fields *fieldmaskpb.FieldMask) (serverVersion uint64, patchedRecords []*databroker.Record, err error)
	// SetCheckpoint sets the latest checkpoint.
	SetCheckpoint(ctx context.Context, serverVersion, recordVersion uint64) error
	// SetOptions sets the options for a type.
	SetOptions(ctx context.Context, recordType string, options *databroker.Options) error
	// Sync syncs record changes after the specified version. If wait is set to
	// true the record iterator will continue to receive records until the
	// iterator or ctx is cancelled.
	Sync(ctx context.Context, recordType string, serverVersion, recordVersion uint64, wait bool) RecordIterator
	// SyncLatest syncs all the records.
	SyncLatest(ctx context.Context, recordType string, filter FilterExpression) (serverVersion, recordVersion uint64, seq RecordIterator, err error)
	// Versions returns versions from the storage backend.
	Versions(ctx context.Context) (serverVersion, latestRecordVersion, earliestRecordVersion uint64, err error)
}

// CleanOptions are the options used for cleaning the storage backend.
type CleanOptions struct {
	RemoveRecordChangesBefore time.Time
}

// MatchAny searches any data with a query.
func MatchAny(a *anypb.Any, query string) bool {
	if a == nil {
		return false
	}

	msg, err := a.UnmarshalNew()
	if err != nil {
		// ignore invalid any types
		log.Error().Err(err).Msg("storage: invalid any type")
		return false
	}

	// search by query
	return matchProtoMessage(msg.ProtoReflect(), query)
}

func matchProtoMessage(msg protoreflect.Message, query string) bool {
	md := msg.Descriptor()
	fds := md.Fields()
	for i := 0; i < fds.Len(); i++ {
		fd := fds.Get(i)
		if !msg.Has(fd) {
			continue
		}
		if matchProtoValue(fd, msg.Get(fd), query) {
			return true
		}
	}
	return false
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
	for i := 0; i < l.Len(); i++ {
		if matchProtoSingularValue(fd, l.Get(i), query) {
			return true
		}
	}
	return false
}

func matchProtoMapValue(fd protoreflect.FieldDescriptor, m protoreflect.Map, query string) bool {
	matches := false
	m.Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
		matches = matches || matchProtoSingularValue(fd, v, query)
		return !matches
	})
	return matches
}

// IsNotFound returns true if the error is because a record was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || status.Code(err) == codes.NotFound
}
