package file

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/pomerium/pomerium/pkg/contextutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (backend *Backend) iterateChangedRecords(
	ctx context.Context,
	recordType string,
	serverVersion, afterRecordVersion uint64,
	wait bool,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx, backend.iteratorCanceler.Context())
	return func(yield func(*databrokerpb.Record, error) bool) {
		defer cancel(nil)

		changed := backend.onRecordChange.Bind()
		defer backend.onRecordChange.Unbind(changed)

		var currentServerVersion, earliestRecordVersion uint64
		err := backend.withReadOnlyTransaction(func(_ readOnlyTransaction) error {
			currentServerVersion = backend.serverVersion
			earliestRecordVersion = backend.earliestRecordVersion
			return nil
		})
		if err != nil {
			yield(nil, err)
			return
		}

		var initErr error
		if serverVersion != currentServerVersion {
			initErr = storage.ErrInvalidServerVersion
		} else if earliestRecordVersion > 0 && afterRecordVersion < (earliestRecordVersion-1) {
			initErr = storage.ErrInvalidRecordVersion
		}

		ctrlRec := storage.ControlFrameRecord()
		if !yield(&ctrlRec, initErr) {
			return
		}
		if initErr != nil {
			return
		}

		for {
			var records []*databrokerpb.Record
			err = backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
				var err error
				records, err = listChangedRecordsAfter(tx, recordType, afterRecordVersion)
				return err
			})
			if err != nil {
				yield(nil, fmt.Errorf("pebble: error listing changed records: %w", err))
				return
			}

			if len(records) > 0 {
				for _, record := range records {
					if !yield(record, nil) {
						return
					}
					afterRecordVersion = max(afterRecordVersion, record.GetVersion())

					select {
					case <-ctx.Done():
						yield(nil, context.Cause(ctx))
						return
					default:
					}
				}
				continue
			}

			if !wait {
				break
			}

			select {
			case <-ctx.Done():
				yield(nil, context.Cause(ctx))
				return
			case <-changed:
			}
		}
	}
}

func (backend *Backend) iterateLatestRecords(
	ctx context.Context,
	recordType string,
	filter storage.FilterExpression,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx, backend.iteratorCanceler.Context())
	return func(yield func(*databrokerpb.Record, error) bool) {
		defer cancel(nil)

		var records []*databrokerpb.Record
		err := backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
			var err error
			records, err = backend.listLatestRecordsLocked(tx, recordType, filter)
			return err
		})
		if err != nil {
			yield(nil, err)
			return
		}

		for _, record := range records {
			if !yield(record, nil) {
				return
			}

			select {
			case <-ctx.Done():
				yield(nil, context.Cause(ctx))
				return
			default:
			}
		}
	}
}

func (backend *Backend) iterateRecordsLocked(
	r reader,
	recordType string,
) iter.Seq2[*databrokerpb.Record, error] {
	if recordType != "" {
		return recordKeySpace.iterate(r, recordType)
	}
	return recordKeySpace.iterateAll(r)
}

func (backend *Backend) iterateRecordsForIDLocked(
	r reader,
	recordType string,
	recordID string,
) iter.Seq2[*databrokerpb.Record, error] {
	// if a record type is specified, retrieve an individual record
	if recordType != "" {
		return func(yield func(*databrokerpb.Record, error) bool) {
			record, err := recordKeySpace.get(r, recordType, recordID)
			if isNotFound(err) {
				return
			}
			yield(record, err)
		}
	}

	// do a lookup for every record type
	var seqs []iter.Seq2[*databrokerpb.Record, error]
	for recordType, err := range recordKeySpace.iterateTypes(r) {
		if err != nil {
			return func(yield func(*databrokerpb.Record, error) bool) {
				yield(nil, err)
			}
		}
		seqs = append(seqs, backend.iterateRecordsForIDLocked(r, recordType, recordID))
	}

	return iterutil.SortedUnionWithError(compareRecords, seqs...)
}

func (backend *Backend) iterateRecordsForIndexLocked(
	r reader,
	recordType string,
	indexValue string,
) iter.Seq2[*databrokerpb.Record, error] {
	if prefix, err := netip.ParsePrefix(indexValue); err == nil {
		return func(yield func(*databrokerpb.Record, error) bool) {
			nodes := backend.recordCIDRIndex.lookupPrefix(recordType, prefix)
			for _, node := range nodes {
				record, err := recordKeySpace.get(r, node.recordType, node.recordID)
				if isNotFound(err) {
					continue
				}
				if !yield(record, err) {
					return
				}
			}
		}
	} else if addr, err := netip.ParseAddr(indexValue); err == nil {
		return func(yield func(*databrokerpb.Record, error) bool) {
			nodes := backend.recordCIDRIndex.lookupAddr(recordType, addr)
			for _, node := range nodes {
				record, err := recordKeySpace.get(r, node.recordType, node.recordID)
				if isNotFound(err) {
					continue
				}
				if !yield(record, err) {
					return
				}
			}
		}
	}
	return func(_ func(*databrokerpb.Record, error) bool) {}
}

func (backend *Backend) iterateRecordsForIndexableFieldsLocked(r reader, idx getByIndex) iter.Seq2[*databrokerpb.Record, error] {
	seq := indexableFieldsKeySpace.get(r, idx)

	return func(yield func(*databrokerpb.Record, error) bool) {
		for recordID, err := range seq {
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}
			if recordID == "" {
				if !yield(nil, fmt.Errorf("no record ID yielded")) {
					return
				}
				continue
			}
			record, err := backend.getRecordLocked(r, idx.recordType, recordID)
			if !yield(record, err) {
				return
			}
		}
	}
}

func (backend *Backend) iterateRecordsForFilterLocked(
	r reader,
	recordType string,
	filter storage.FilterExpression,
) iter.Seq2[*databrokerpb.Record, error] {
	if filter == nil {
		return backend.iterateRecordsLocked(r, recordType)
	}

	switch filter := filter.(type) {
	case storage.AndFilterExpression:
		seqs := make([]iter.Seq2[*databrokerpb.Record, error], len(filter))
		for i, f := range filter {
			seqs[i] = backend.iterateRecordsForFilterLocked(r, recordType, f)
		}
		return iterutil.SortedIntersectionWithError(compareRecords, seqs...)
	case storage.OrFilterExpression:
		seqs := make([]iter.Seq2[*databrokerpb.Record, error], len(filter))
		for i, f := range filter {
			seqs[i] = backend.iterateRecordsForFilterLocked(r, recordType, f)
		}
		return iterutil.SortedUnionWithError(compareRecords, seqs...)
	case storage.EqualsFilterExpression:
		switch {
		case slices.Equal(filter.Fields, []string{"id"}):
			return backend.iterateRecordsForIDLocked(r, recordType, filter.Value)
		case slices.Equal(filter.Fields, []string{"$index"}):
			return backend.iterateRecordsForIndexLocked(r, recordType, filter.Value)
		default:
			return backend.iterateRecordsForIndexableFieldsLocked(r, getByIndex{
				recordType: recordType,
				field:      strings.Join(filter.Fields, "."),
				fieldValue: filter.Value,
			})
		}
	default:
		return func(yield func(*databrokerpb.Record, error) bool) {
			yield(nil, fmt.Errorf("unsupported filter type: %T", filter))
		}
	}
}
