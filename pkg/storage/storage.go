// Package storage provide generic interface to interact with storage backend.
package storage

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Backend is the interface required for a storage backend.
type Backend interface {
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
}
