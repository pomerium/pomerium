package file

import (
	"fmt"
	"iter"
	"slices"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/pebbleutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestKeyspaces(t *testing.T) {
	t.Parallel()

	t.Run("metadata", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		version, err := metadataKeySpace.getEarliestRecordVersion(db)
		assert.Equal(t, uint64(0), version)
		assert.ErrorIs(t, err, pebble.ErrNotFound)

		err = metadataKeySpace.setEarliestRecordVersion(db, 12)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getEarliestRecordVersion(db)
		assert.Equal(t, uint64(12), version)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getLatestRecordVersion(db)
		assert.Equal(t, uint64(0), version)
		assert.ErrorIs(t, err, pebble.ErrNotFound)

		err = metadataKeySpace.setLatestRecordVersion(db, 34)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getLatestRecordVersion(db)
		assert.Equal(t, uint64(34), version)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getServerVersion(db)
		assert.Equal(t, uint64(0), version)
		assert.ErrorIs(t, err, pebble.ErrNotFound)

		err = metadataKeySpace.setServerVersion(db, 56)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getServerVersion(db)
		assert.Equal(t, uint64(56), version)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getMigration(db)
		assert.Equal(t, uint64(0), version)
		assert.ErrorIs(t, err, pebble.ErrNotFound)

		err = metadataKeySpace.setMigration(db, 78)
		assert.NoError(t, err)

		version, err = metadataKeySpace.getMigration(db)
		assert.Equal(t, uint64(78), version)
		assert.NoError(t, err)

		assert.Equal(t, [][2][]byte{
			{{0x02, 0x01}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c}},
			{{0x02, 0x02}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22}},
			{{0x02, 0x03}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38}},
			{{0x02, 0x04}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e}},
		}, dumpDatabase(t, db))
	})
	t.Run("lease", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		_, _, err := leaseKeySpace.get(db, "unknown-lease")
		assert.ErrorIs(t, err, pebble.ErrNotFound)

		for i := range 10 {
			err := leaseKeySpace.set(db,
				fmt.Sprintf("lease-%d", i),
				fmt.Sprintf("id-%d", i),
				time.Date(2025, 8, 4, 15, 0, 0, i*1000, time.UTC),
			)
			assert.NoError(t, err)
		}
		for i := range 10 {
			leaseID, expiresAt, err := leaseKeySpace.get(db, fmt.Sprintf("lease-%d", i))
			assert.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("id-%d", i), leaseID)
			assert.Equal(t, time.Date(2025, 8, 4, 15, 0, 0, i*1000, time.UTC), expiresAt)
		}
		assert.Equal(t, [][2][]byte{
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x30}, {0x69, 0x64, 0x2d, 0x30, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x00}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x31}, {0x69, 0x64, 0x2d, 0x31, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x01}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x32}, {0x69, 0x64, 0x2d, 0x32, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x02}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x33}, {0x69, 0x64, 0x2d, 0x33, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x03}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x34}, {0x69, 0x64, 0x2d, 0x34, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x04}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x35}, {0x69, 0x64, 0x2d, 0x35, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x05}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x36}, {0x69, 0x64, 0x2d, 0x36, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x06}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x37}, {0x69, 0x64, 0x2d, 0x37, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x07}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x38}, {0x69, 0x64, 0x2d, 0x38, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x08}},
			{{0x01, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x39}, {0x69, 0x64, 0x2d, 0x39, 0x00, 0x00, 0x06, 0x3b, 0x8b, 0x5c, 0x94, 0x9c, 0x09}},
		}, dumpDatabase(t, db))
	})
	t.Run("record", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		// check bounds
		lowerBound, upperBound := recordKeySpace.bounds()
		assert.Equal(t, []byte{0x06}, lowerBound)
		assert.Equal(t, []byte{0x07}, upperBound)

		record, err := recordKeySpace.get(db, "t1", "i1")
		assert.ErrorIs(t, err, pebble.ErrNotFound)
		assert.Nil(t, record)

		for i := range 10 {
			recordType, recordID := fmt.Sprintf("t%d", i%2), fmt.Sprintf("i%d", i)
			err = recordKeySpace.set(db, &databrokerpb.Record{
				Version: uint64(i + 1),
				Type:    recordType,
				Id:      recordID,
			})
			assert.NoError(t, err)
		}
		for i := range 10 {
			recordType, recordID := fmt.Sprintf("t%d", i%2), fmt.Sprintf("i%d", i)
			record, err = recordKeySpace.get(db, recordType, recordID)
			assert.NoError(t, err)
			assert.Empty(t, cmp.Diff(&databrokerpb.Record{
				Version: uint64(i + 1),
				Type:    recordType,
				Id:      recordID,
			}, record, protocmp.Transform()))
		}
		assert.Equal(t, [][2][]byte{
			{{0x06, 't', '0', 0x00, 'i', '0'}, {0x08, 0x01, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '0'}},
			{{0x06, 't', '0', 0x00, 'i', '2'}, {0x08, 0x03, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '2'}},
			{{0x06, 't', '0', 0x00, 'i', '4'}, {0x08, 0x05, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '4'}},
			{{0x06, 't', '0', 0x00, 'i', '6'}, {0x08, 0x07, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '6'}},
			{{0x06, 't', '0', 0x00, 'i', '8'}, {0x08, 0x09, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '8'}},
			{{0x06, 't', '1', 0x00, 'i', '1'}, {0x08, 0x02, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '1'}},
			{{0x06, 't', '1', 0x00, 'i', '3'}, {0x08, 0x04, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '3'}},
			{{0x06, 't', '1', 0x00, 'i', '5'}, {0x08, 0x06, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '5'}},
			{{0x06, 't', '1', 0x00, 'i', '7'}, {0x08, 0x08, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '7'}},
			{{0x06, 't', '1', 0x00, 'i', '9'}, {0x08, 0x0a, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '9'}},
		}, dumpDatabase(t, db))

		records, err := storage.RecordIteratorToList(recordKeySpace.iterateAll(db))
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff([]*databrokerpb.Record{
			{Type: "t0", Id: "i0", Version: 1},
			{Type: "t0", Id: "i2", Version: 3},
			{Type: "t0", Id: "i4", Version: 5},
			{Type: "t0", Id: "i6", Version: 7},
			{Type: "t0", Id: "i8", Version: 9},
			{Type: "t1", Id: "i1", Version: 2},
			{Type: "t1", Id: "i3", Version: 4},
			{Type: "t1", Id: "i5", Version: 6},
			{Type: "t1", Id: "i7", Version: 8},
			{Type: "t1", Id: "i9", Version: 10},
		}, records, protocmp.Transform()))

		// delete the records
		for i := range 10 {
			recordType, recordID := fmt.Sprintf("t%d", i%2), fmt.Sprintf("i%d", i)
			err = recordKeySpace.delete(db, recordType, recordID)
			assert.NoError(t, err)
		}
		assert.Equal(t, [][2][]byte{}, dumpDatabase(t, db))
	})
	t.Run("record-index-by-type-version", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		// check bounds
		lowerBound, upperBound := recordIndexByTypeVersionKeySpace.bounds("T")
		assert.Equal(t, []byte{0x07, 0x54, 0x00}, lowerBound)
		assert.Equal(t, []byte{0x07, 0x54, 0x01}, upperBound)

		for i := range 10 {
			recordType, recordID := fmt.Sprintf("t%d", i%2), fmt.Sprintf("i%d", i)
			err := recordIndexByTypeVersionKeySpace.set(db, recordType, recordID, uint64(1000-i))
			assert.NoError(t, err)
		}

		ids, err := toList(recordIndexByTypeVersionKeySpace.iterateIDsReversed(db, "t0"))
		assert.NoError(t, err)
		assert.Equal(t, []string{"i0", "i2", "i4", "i6", "i8"}, ids)

		ids, err = toList(recordIndexByTypeVersionKeySpace.iterateIDsReversed(db, "t1"))
		assert.NoError(t, err)
		assert.Equal(t, []string{"i1", "i3", "i5", "i7", "i9"}, ids)
	})
	t.Run("record-change", func(t *testing.T) {
		t.Parallel()

		// db := pebbleutil.MustOpenMemory(nil)

		// check bounds
		lowerBound, upperBound := recordChangeKeySpace.bounds(32)
		assert.Equal(t, []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21}, lowerBound)
		assert.Equal(t, []byte{0x05}, upperBound)
	})
}

func dumpDatabase(t testing.TB, r pebble.Reader) [][2][]byte {
	t.Helper()

	kvs := make([][2][]byte, 0)
	for kv, err := range pebbleutil.Iterate(r, nil, func(it *pebble.Iterator) ([2][]byte, error) {
		key := slices.Clone(it.Key())
		value := slices.Clone(it.Value())
		return [2][]byte{key, value}, it.Error()
	}) {
		require.NoError(t, err)
		kvs = append(kvs, kv)
	}
	return kvs
}

func toList[T any](seq iter.Seq2[T, error]) ([]T, error) {
	var s []T
	for e, err := range seq {
		if err != nil {
			return nil, err
		}
		s = append(s, e)
	}
	return s, nil
}
