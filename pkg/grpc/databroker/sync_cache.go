package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"

	pebble "github.com/cockroachdb/pebble/v2"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/pebbleutil"
)

const (
	fieldServerVersion byte = 1
	fieldRecordVersion byte = 2
	fieldRecord        byte = 3
)

var (
	syncCacheUUIDNamespace = uuid.MustParse("c9acb8d4-f10a-4e3c-9308-c285e1ebfb58")
	marshalOptions         = &proto.MarshalOptions{AllowPartial: true, Deterministic: true}
	unmarshalOptions       = &proto.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}
)

// A SyncCache uses the databroker Sync and SyncLatest methods to populate a cache of records.
// To use the SyncCache call Sync followed by Records.
//
// Data is stored in a pebble database in this format:
//
//	{{prefix}}{{uuidv5(recordType)}}0x01: the server version
//	{{prefix}}{{uuidv5(recordType)}}0x02: the latest record version
//	{{prefix}}{{uuidv5(recordType)}}0x03{{recordID}}: a databroker record
//
// Values are protobuf encoded.
type SyncCache interface {
	// Clear deletes all the data for the given record type in the sync cache.
	Clear(recordType string) error
	// Records yields the databroker records stored in the cache.
	Records(recordType string) iter.Seq2[*Record, error]
	// Sync syncs the cache with the databroker.
	Sync(ctx context.Context, client DataBrokerServiceClient, recordType string) error
}

type syncCache struct {
	db     *pebble.DB
	prefix []byte

	iterOptions  *pebble.IterOptions
	writeOptions *pebble.WriteOptions
}

// NewSyncCache creates a new SyncCache.
func NewSyncCache(db *pebble.DB, prefix []byte) SyncCache {
	return &syncCache{
		db:     db,
		prefix: prefix,
	}
}

func (c *syncCache) Clear(recordType string) error {
	// delete all the existing data
	err := c.pebbleDeletePrefix(c.db, c.recordTypePrefix(recordType))
	if err != nil {
		return fmt.Errorf("sync-cache: error clearing data from cache (record-type=%s): %w", recordType, err)
	}

	return nil
}

func (c *syncCache) Records(recordType string) iter.Seq2[*Record, error] {
	prefix := c.recordPrefix(recordType)
	iterOptions := new(pebble.IterOptions)
	if c.iterOptions != nil {
		*iterOptions = *c.iterOptions
	}
	iterOptions.LowerBound = prefix
	iterOptions.UpperBound = pebbleutil.PrefixToUpperBound(prefix)
	return func(yield func(*Record, error) bool) {
		for record, err := range pebbleutil.Iterate(c.db, iterOptions, pebbleIteratorToRecord) {
			if err != nil {
				yield(nil, fmt.Errorf("sync-cache: error iterating over cached records (record-type=%s): %w", recordType, err))
				return
			}

			if !yield(record, nil) {
				return
			}
		}
	}
}

func (c *syncCache) Sync(ctx context.Context, client DataBrokerServiceClient, recordType string) error {
	serverVersion, recordVersion := wrapperspb.UInt64(0), wrapperspb.UInt64(0)
	err := errors.Join(
		c.pebbleGetProto(c.db, c.serverVersionKey(recordType), serverVersion),
		c.pebbleGetProto(c.db, c.recordVersionKey(recordType), recordVersion),
	)
	if errors.Is(err, pebble.ErrNotFound) {
		// if we've never synced, use sync latest
		return c.syncLatest(ctx, client, recordType)
	} else if err != nil {
		return fmt.Errorf("sync-cache: error retrieving server and record version from cache (record-type=%s): %w", recordType, err)
	}

	return c.sync(ctx, client, recordType, serverVersion.Value, recordVersion.Value)
}

func (c *syncCache) recordKey(recordType, recordID string) []byte {
	return slices.Concat(c.recordPrefix(recordType), []byte(recordID))
}

func (c *syncCache) recordPrefix(recordType string) []byte {
	return append(c.recordTypePrefix(recordType), fieldRecord)
}

func (c *syncCache) recordTypePrefix(recordType string) []byte {
	id := uuid.NewSHA1(syncCacheUUIDNamespace, []byte(recordType))
	return slices.Concat(c.prefix, id[:])
}

func (c *syncCache) recordVersionKey(recordType string) []byte {
	return append(c.recordTypePrefix(recordType), fieldRecordVersion)
}

func (c *syncCache) serverVersionKey(recordType string) []byte {
	return append(c.recordTypePrefix(recordType), fieldServerVersion)
}

func (c *syncCache) sync(ctx context.Context, client DataBrokerServiceClient, recordType string, serverVersion, recordVersion uint64) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.Sync(ctx, &SyncRequest{
		Type:          recordType,
		ServerVersion: serverVersion,
		RecordVersion: recordVersion,
		Wait:          proto.Bool(false),
	})
	if err != nil {
		return fmt.Errorf("sync-cache: error starting sync stream (record-type=%s): %w", recordType, err)
	}

	// batch the updates together
	batch := c.db.NewBatch()
	defer batch.Close()

	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if status.Code(err) == codes.Aborted {
			// the server version changed, so use sync latest
			return c.syncLatest(ctx, client, recordType)
		} else if err != nil {
			return fmt.Errorf("sync-cache: error receiving message from sync stream (record-type=%s): %w", recordType, err)
		}

		// either delete or update the record
		if res.Record.DeletedAt != nil {
			err = c.pebbleDelete(batch, c.recordKey(recordType, res.Record.Id))
		} else {
			err = c.pebbleSetProto(batch, c.recordKey(recordType, res.Record.Id), res.Record)
		}
		if err != nil {
			return fmt.Errorf("sync-cache: error updating record in cache (record-type=%s): %w", recordType, err)
		}

		// update the record version
		recordVersion = max(recordVersion, res.Record.Version)
		err = c.pebbleSetProto(batch, c.recordVersionKey(recordType), wrapperspb.UInt64(recordVersion))
		if err != nil {
			return fmt.Errorf("sync-cache: error updating record version in cache (record-type=%s): %w", recordType, err)
		}
	}

	err = batch.Commit(c.writeOptions)
	if err != nil {
		return fmt.Errorf("sync-cache: error committing changes to cache (record-type=%s): %w", recordType, err)
	}

	return nil
}

func (c *syncCache) syncLatest(ctx context.Context, client DataBrokerServiceClient, recordType string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.SyncLatest(ctx, &SyncLatestRequest{
		Type: recordType,
	})
	if err != nil {
		return fmt.Errorf("sync-cache: error starting sync latest stream (record-type=%s): %w", recordType, err)
	}

	// batch the updates together
	batch := c.db.NewBatch()
	defer batch.Close()

	// delete all the existing data
	err = c.pebbleDeletePrefix(batch, c.recordTypePrefix(recordType))
	if err != nil {
		return fmt.Errorf("sync-cache: error deleting existing data from cache (record-type=%s): %w", recordType, err)
	}

	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("sync-cache: error receiving message from sync latest stream (record-type=%s): %w", recordType, err)
		}

		switch res := res.Response.(type) {
		case *SyncLatestResponse_Record:
			// add the record
			err = c.pebbleSetProto(batch, c.recordKey(recordType, res.Record.Id), res.Record)
			if err != nil {
				return fmt.Errorf("sync-cache: error saving record to cache (record-type=%s): %w", recordType, err)
			}
		case *SyncLatestResponse_Versions:
			// update the versions
			err = errors.Join(
				c.pebbleSetProto(batch, c.serverVersionKey(recordType), wrapperspb.UInt64(res.Versions.ServerVersion)),
				c.pebbleSetProto(batch, c.recordVersionKey(recordType), wrapperspb.UInt64(res.Versions.LatestRecordVersion)),
			)
			if err != nil {
				return fmt.Errorf("sync-cache: error saving versions to cache (record-type=%s): %w", recordType, err)
			}
		default:
			return fmt.Errorf("sync-cache: unknown message type from sync latest stream (record-type=%s): %T", recordType, res)
		}
	}

	err = batch.Commit(c.writeOptions)
	if err != nil {
		return fmt.Errorf("sync-cache: error committing changes to cache (record-type=%s): %w", recordType, err)
	}

	return nil
}

func (c *syncCache) pebbleDelete(dst pebble.Writer, key []byte) error {
	return dst.Delete(key, c.writeOptions)
}

func (c *syncCache) pebbleDeletePrefix(dst pebble.Writer, prefix []byte) error {
	return dst.DeleteRange(prefix, pebbleutil.PrefixToUpperBound(prefix), c.writeOptions)
}

func (c *syncCache) pebbleGetProto(src pebble.Reader, key []byte, msg proto.Message) error {
	value, closer, err := src.Get(key)
	if err != nil {
		return err
	}
	err = unmarshalOptions.Unmarshal(value, msg)
	_ = closer.Close()
	return err
}

func (c *syncCache) pebbleSet(dst pebble.Writer, key, value []byte) error {
	return dst.Set(key, value, c.writeOptions)
}

func (c *syncCache) pebbleSetProto(dst pebble.Writer, key []byte, msg proto.Message) error {
	value, err := marshalOptions.Marshal(msg)
	if err != nil {
		return err
	}
	return c.pebbleSet(dst, key, value)
}

func pebbleIteratorToRecord(it *pebble.Iterator) (*Record, error) {
	value, err := it.ValueAndErr()
	if err != nil {
		return nil, err
	}

	record := new(Record)
	err = unmarshalOptions.Unmarshal(value, record)
	if err != nil {
		return nil, err
	}

	return record, nil
}
