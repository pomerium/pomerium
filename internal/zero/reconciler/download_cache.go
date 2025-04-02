package reconciler

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/log"
	zero_sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// BundleCacheEntry is a cache entry for a bundle
// that is kept in the databroker to avoid downloading
// the same bundle multiple times.
//
// by using the ETag and LastModified headers, we do not need to
// keep caches of the bundles themselves, which can be large.
//
// also it works in case of multiple instances, as it uses
// the databroker database as a shared cache.
type BundleCacheEntry struct {
	zero_sdk.DownloadConditional
	RecordTypes []string
}

const (
	// BundleCacheEntryRecordType is the databroker record type for BundleCacheEntry
	BundleCacheEntryRecordType = "pomerium.io/BundleCacheEntry"
)

// ErrBundleCacheEntryNotFound is returned when a bundle cache entry is not found
var ErrBundleCacheEntryNotFound = errors.New("bundle cache entry not found")

// GetBundleCacheEntry gets a bundle cache entry from the databroker
func (c *service) GetBundleCacheEntry(ctx context.Context, id string) (*BundleCacheEntry, error) {
	record, err := c.config.databrokerClient.Get(ctx, &databroker.GetRequest{
		Type: BundleCacheEntryRecordType,
		Id:   id,
	})
	if err != nil && status.Code(err) == codes.NotFound {
		return nil, ErrBundleCacheEntryNotFound
	} else if err != nil {
		return nil, fmt.Errorf("get bundle cache entry: %w", err)
	}

	var dst BundleCacheEntry
	data := record.GetRecord().GetData()
	err = dst.FromAny(data)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("bundle-id", id).
			Str("data", protojson.Format(data)).
			Msg("could not unmarshal bundle cache entry")
		// we would allow it to be overwritten by the update process
		return nil, ErrBundleCacheEntryNotFound
	}

	return &dst, nil
}

// SetBundleCacheEntry sets a bundle cache entry in the databroker
func (c *service) SetBundleCacheEntry(ctx context.Context, id string, src BundleCacheEntry) error {
	val, err := src.ToAny()
	if err != nil {
		return fmt.Errorf("marshal bundle cache entry: %w", err)
	}
	_, err = c.config.databrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type: BundleCacheEntryRecordType,
				Id:   id,
				Data: val,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("set bundle cache entry: %w", err)
	}
	return nil
}

// ToAny marshals a BundleCacheEntry into an anypb.Any
func (r *BundleCacheEntry) ToAny() (*anypb.Any, error) {
	err := r.Validate()
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	types := make([]*structpb.Value, 0, len(r.RecordTypes))
	for _, t := range r.RecordTypes {
		types = append(types, structpb.NewStringValue(t))
	}

	return protoutil.NewAny(&structpb.Struct{
		Fields: map[string]*structpb.Value{
			"etag":          structpb.NewStringValue(r.ETag),
			"last_modified": structpb.NewStringValue(r.LastModified),
			"record_types":  structpb.NewListValue(&structpb.ListValue{Values: types}),
		},
	}), nil
}

// FromAny unmarshals an anypb.Any into a BundleCacheEntry
func (r *BundleCacheEntry) FromAny(a *anypb.Any) error {
	var s structpb.Struct
	err := a.UnmarshalTo(&s)
	if err != nil {
		return fmt.Errorf("unmarshal struct: %w", err)
	}

	r.ETag = s.GetFields()["etag"].GetStringValue()
	r.LastModified = s.GetFields()["last_modified"].GetStringValue()

	for _, v := range s.GetFields()["record_types"].GetListValue().GetValues() {
		r.RecordTypes = append(r.RecordTypes, v.GetStringValue())
	}

	err = r.Validate()
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	return nil
}

// Validate validates a BundleCacheEntry
func (r *BundleCacheEntry) Validate() error {
	var errs *multierror.Error
	if len(r.RecordTypes) == 0 {
		errs = multierror.Append(errs, errors.New("record_types is required"))
	}
	if err := r.DownloadConditional.Validate(); err != nil {
		errs = multierror.Append(errs, err)
	}
	return errs.ErrorOrNil()
}

// GetDownloadConditional returns conditional download information
func (r *BundleCacheEntry) GetDownloadConditional() *zero_sdk.DownloadConditional {
	if r == nil {
		return nil
	}
	cond := r.DownloadConditional
	return &cond
}

// GetRecordTypes returns the record types
func (r *BundleCacheEntry) GetRecordTypes() []string {
	if r == nil {
		return nil
	}
	return r.RecordTypes
}

// Equals returns true if the two cache entries are equal
func (r *BundleCacheEntry) Equals(other *BundleCacheEntry) bool {
	return r != nil && other != nil &&
		r.ETag == other.ETag && r.LastModified == other.LastModified
}
