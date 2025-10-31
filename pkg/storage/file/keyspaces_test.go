package file

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/pebbleutil"
)

func TestKeyspaces(t *testing.T) {
	t.Parallel()

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

	t.Run("indexable fields", func(t *testing.T) {
		t.Parallel()
		db := pebbleutil.MustOpenMemory(nil)

		type getTc struct {
			req getByIndex
			ids []string
			err error
		}

		indices := []index{
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userA",
				recordID:   "s1",
			},
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userA",
				recordID:   "s2",
			},
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userB",
				recordID:   "s3",
			},
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userB",
				recordID:   "s4",
			},
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userC",
				recordID:   "s5",
			},
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userC",
				recordID:   "s6",
			},
			{
				recordType: "session2",
				field:      "user_id",
				fieldValue: "userA",
				recordID:   "s1",
			},
			{
				recordType: "session2",
				field:      "user_id",
				fieldValue: "userB",
				recordID:   "s2",
			},
			{
				recordType: "session2",
				field:      "user_id",
				fieldValue: "userA",
				recordID:   "s3",
			},
			{
				recordType: "session2",
				field:      "user_id",
				fieldValue: "userB",
				recordID:   "s4",
			},
		}

		for _, idx := range indices {
			assert.NoError(t, indexableFieldsKeySpace.set(db, idx))
		}

		tcs := []getTc{
			{
				req: getByIndex{
					recordType: "session",
					field:      "user_id",
					fieldValue: "userA",
				},
				ids: []string{"s1", "s2"},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session",
					field:      "user_id",
					fieldValue: "userB",
				},
				ids: []string{"s3", "s4"},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session",
					field:      "user_id",
					fieldValue: "userC",
				},
				ids: []string{"s5", "s6"},
				err: nil,
			},
		}

		for _, tc := range tcs {
			got, err := iterutil.CollectWithError(indexableFieldsKeySpace.get(db, tc.req))
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.ElementsMatch(t, tc.ids, got)
			}
		}

		noIndexReq := []getByIndex{
			// field value that hasn't been indexed
			{
				recordType: "session",
				field:      "user_id",
				fieldValue: "userD",
			},
			// field that hasn't been indexed
			{
				recordType: "session",
				field:      "none",
				fieldValue: "userA",
			},
			// record type that hasn't been indexed
			{
				recordType: "sessionBinding",
				field:      "user_id",
				fieldValue: "userA",
			},
		}

		for idx, req := range noIndexReq {
			ids, err := iterutil.CollectWithError(indexableFieldsKeySpace.get(db, req))
			assert.NoError(t, err, fmt.Sprintf("no index recorded test case :%d failed", idx))
			assert.ElementsMatch(t, []string{}, ids, fmt.Sprintf("no index recorded test case :%d failed", idx))
		}

		assert.NoError(t, indexableFieldsKeySpace.deleteByIndex(db, "session", "no-such-field"))
		assert.NoError(t, indexableFieldsKeySpace.deleteByIndex(db, "session", "user_id"))

		tcs2 := []getTc{
			{
				req: getByIndex{
					recordType: "session",
					field:      "user_id",
					fieldValue: "userA",
				},
				ids: []string{},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session",
					field:      "user_id",
					fieldValue: "userB",
				},
				ids: []string{},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session",
					field:      "user_id",
					fieldValue: "userC",
				},
				ids: []string{},
				err: nil,
			},
		}

		for _, tc := range tcs2 {
			got, err := iterutil.CollectWithError(indexableFieldsKeySpace.get(db, tc.req))
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.ElementsMatch(t, tc.ids, got)
			}
		}

		tcs3 := []getTc{
			{
				req: getByIndex{
					recordType: "session2",
					field:      "user_id",
					fieldValue: "userA",
				},
				ids: []string{"s1", "s3"},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session2",
					field:      "user_id",
					fieldValue: "userB",
				},
				ids: []string{"s2", "s4"},
				err: nil,
			},
		}

		for _, tc := range tcs3 {
			got, err := iterutil.CollectWithError(indexableFieldsKeySpace.get(db, tc.req))
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.ElementsMatch(t, tc.ids, got)
			}
		}

		// edit
		assert.NoError(t, indexableFieldsKeySpace.set(db, index{
			recordType: "session2",
			field:      "user_id",
			fieldValue: "userC",
			recordID:   "s2",
		}),
		)

		// delete
		assert.NoError(t, indexableFieldsKeySpace.delete(db, index{
			recordType: "session2",
			field:      "user_id",
			fieldValue: "userA",
			recordID:   "s1",
		}))

		tcs4 := []getTc{
			{
				req: getByIndex{
					recordType: "session2",
					field:      "user_id",
					fieldValue: "userA",
				},
				ids: []string{"s3"},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session2",
					field:      "user_id",
					fieldValue: "userB",
				},
				// it's up to the caller to clean these up; in the context
				// this is meant to be used this would be trated as invalid to have
				// s2 be indexed both by user_id=userB & user_id=userC
				ids: []string{"s2", "s4"},
				err: nil,
			},
			{
				req: getByIndex{
					recordType: "session2",
					field:      "user_id",
					fieldValue: "userC",
				},
				ids: []string{"s2"},
				err: nil,
			},
		}

		for _, tc := range tcs4 {
			got, err := iterutil.CollectWithError(indexableFieldsKeySpace.get(db, tc.req))
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.ElementsMatch(t, tc.ids, got)
			}
		}
	})

	t.Run("metadata", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		version, err := metadataKeySpace.getServerVersion(db)
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
			{{0x02, 0x01}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38}},
			{{0x02, 0x02}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e}},
		}, dumpDatabase(t, db))
	})
	t.Run("options", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		lowerBound, upperBound := optionsKeySpace.bounds()
		assert.Equal(t, []byte{0x03}, lowerBound)
		assert.Equal(t, []byte{0x04}, upperBound)

		for i := range 10 {
			assert.NoError(t, optionsKeySpace.set(db,
				fmt.Sprintf("t%d", i),
				&databrokerpb.Options{Capacity: proto.Uint64(uint64(i))}))
		}

		assert.Equal(t, [][2][]byte{
			{{0x03, 't', '0'}, {0x08, 0x00}},
			{{0x03, 't', '1'}, {0x08, 0x01}},
			{{0x03, 't', '2'}, {0x08, 0x02}},
			{{0x03, 't', '3'}, {0x08, 0x03}},
			{{0x03, 't', '4'}, {0x08, 0x04}},
			{{0x03, 't', '5'}, {0x08, 0x05}},
			{{0x03, 't', '6'}, {0x08, 0x06}},
			{{0x03, 't', '7'}, {0x08, 0x07}},
			{{0x03, 't', '8'}, {0x08, 0x08}},
			{{0x03, 't', '9'}, {0x08, 0x09}},
		}, dumpDatabase(t, db))

		nodes, err := iterutil.CollectWithError(optionsKeySpace.iterate(db))
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(
			[]optionsNode{
				{"t0", &databrokerpb.Options{Capacity: proto.Uint64(0)}},
				{"t1", &databrokerpb.Options{Capacity: proto.Uint64(1)}},
				{"t2", &databrokerpb.Options{Capacity: proto.Uint64(2)}},
				{"t3", &databrokerpb.Options{Capacity: proto.Uint64(3)}},
				{"t4", &databrokerpb.Options{Capacity: proto.Uint64(4)}},
				{"t5", &databrokerpb.Options{Capacity: proto.Uint64(5)}},
				{"t6", &databrokerpb.Options{Capacity: proto.Uint64(6)}},
				{"t7", &databrokerpb.Options{Capacity: proto.Uint64(7)}},
				{"t8", &databrokerpb.Options{Capacity: proto.Uint64(8)}},
				{"t9", &databrokerpb.Options{Capacity: proto.Uint64(9)}},
			},
			nodes,
			cmp.AllowUnexported(optionsNode{}),
			protocmp.Transform()))

		for i := range 9 {
			assert.NoError(t, optionsKeySpace.delete(db, fmt.Sprintf("t%d", i)))
		}

		assert.Equal(t, [][2][]byte{
			{{0x03, 't', '9'}, {0x08, 0x09}},
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

		records, err := iterutil.CollectWithError(recordKeySpace.iterateAll(db))
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

		ids, err := iterutil.CollectWithError(recordIndexByTypeVersionKeySpace.iterateIDsReversed(db, "t0"))
		assert.NoError(t, err)
		assert.Equal(t, []string{"i0", "i2", "i4", "i6", "i8"}, ids)

		ids, err = iterutil.CollectWithError(recordIndexByTypeVersionKeySpace.iterateIDsReversed(db, "t1"))
		assert.NoError(t, err)
		assert.Equal(t, []string{"i1", "i3", "i5", "i7", "i9"}, ids)
	})
	t.Run("record-change", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		// check bounds
		lowerBound, upperBound := recordChangeKeySpace.bounds(32)
		assert.Equal(t, []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21}, lowerBound)
		assert.Equal(t, []byte{0x05}, upperBound)

		for i := range 10 {
			recordType, recordID := fmt.Sprintf("t%d", i%2), fmt.Sprintf("i%d", i)
			err := recordChangeKeySpace.set(db, &databrokerpb.Record{
				Version: uint64(i + 1),
				Type:    recordType,
				Id:      recordID,
			})
			assert.NoError(t, err)
		}

		assert.Equal(t, [][2][]byte{
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, {0x08, 0x01, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '0'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, {0x08, 0x02, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '1'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, {0x08, 0x03, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '2'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}, {0x08, 0x04, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '3'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}, {0x08, 0x05, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '4'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}, {0x08, 0x06, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '5'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07}, {0x08, 0x07, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '6'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}, {0x08, 0x08, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '7'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}, {0x08, 0x09, 0x12, 0x02, 't', '0', 0x1a, 0x02, 'i', '8'}},
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}, {0x08, 0x0a, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '9'}},
		}, dumpDatabase(t, db))

		version, err := recordChangeKeySpace.getFirstVersion(db)
		assert.NoError(t, err)
		assert.Equal(t, uint64(1), version)

		version, err = recordChangeKeySpace.getLastVersion(db)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), version)

		record, err := recordChangeKeySpace.get(db, 3)
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(&databrokerpb.Record{
			Type:    "t0",
			Id:      "i2",
			Version: 3,
		}, record, protocmp.Transform()))

		records, err := iterutil.CollectWithError(recordChangeKeySpace.iterate(db, 8))
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff([]*databrokerpb.Record{
			{
				Type:    "t0",
				Id:      "i8",
				Version: 9,
			},
			{
				Type:    "t1",
				Id:      "i9",
				Version: 10,
			},
		}, records, protocmp.Transform()))

		for i := range 9 {
			assert.NoError(t, recordChangeKeySpace.delete(db, uint64(i+1)))
		}

		assert.Equal(t, [][2][]byte{
			{{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}, {0x08, 0x0a, 0x12, 0x02, 't', '1', 0x1a, 0x02, 'i', '9'}},
		}, dumpDatabase(t, db))
	})
	t.Run("record-change-index-by-type", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)

		// check bounds
		lowerBound, upperBound := recordChangeIndexByTypeKeySpace.bounds("t", 8)
		assert.Equal(t, []byte{0x05, 't', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}, lowerBound)
		assert.Equal(t, []byte{0x05, 'u'}, upperBound)

		for i := range 10 {
			recordType, version := fmt.Sprintf("t%d", i%2), uint64(i+1)
			assert.NoError(t, recordChangeIndexByTypeKeySpace.set(db, recordType, version))
		}

		assert.Equal(t, [][2][]byte{
			{{0x05, 't', '0', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, {}},
			{{0x05, 't', '0', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, {}},
			{{0x05, 't', '0', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}, {}},
			{{0x05, 't', '0', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07}, {}},
			{{0x05, 't', '0', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}, {}},
			{{0x05, 't', '1', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, {}},
			{{0x05, 't', '1', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}, {}},
			{{0x05, 't', '1', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}, {}},
			{{0x05, 't', '1', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}, {}},
			{{0x05, 't', '1', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}, {}},
		}, dumpDatabase(t, db))

		for i := range 10 {
			recordType, recordID, version := fmt.Sprintf("t%d", i%2), fmt.Sprintf("i%d", i), uint64(i+1)
			assert.NoError(t, recordChangeKeySpace.set(db, &databrokerpb.Record{
				Version: version,
				Type:    recordType,
				Id:      recordID,
			}))
		}

		records, err := iterutil.CollectWithError(recordChangeIndexByTypeKeySpace.iterate(db, "t0", 8))
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff([]*databrokerpb.Record{
			{
				Type:    "t0",
				Id:      "i8",
				Version: 9,
			},
		}, records, protocmp.Transform()))
	})
	t.Run("registry-service", func(t *testing.T) {
		t.Parallel()

		db := pebbleutil.MustOpenMemory(nil)
		tm0 := time.Date(2025, 8, 7, 0, 0, 0, 0, time.UTC)

		// check bounds
		lowerBound, upperBound := registryServiceKeySpace.bounds()
		assert.Equal(t, []byte{0x08}, lowerBound)
		assert.Equal(t, []byte{0x09}, upperBound)

		for i := range 10 {
			assert.NoError(t, registryServiceKeySpace.set(db, registryServiceNode{
				kind:      registry.ServiceKind(i%2 + 1),
				endpoint:  fmt.Sprintf("%d", i),
				expiresAt: tm0,
			}))
		}

		assert.Equal(t, [][2][]byte{
			{{0x08, 0x01, '0'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x01, '2'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x01, '4'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x01, '6'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x01, '8'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x02, '1'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x02, '3'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x02, '5'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x02, '7'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
			{{0x08, 0x02, '9'}, {0x00, 0x06, 0x3b, 0xbb, 0x23, 0x74, 0x20, 0x00}},
		}, dumpDatabase(t, db))

		nodes, err := iterutil.CollectWithError(registryServiceKeySpace.iterate(db))
		assert.NoError(t, err)
		assert.Equal(t, []registryServiceNode{
			{registry.ServiceKind_DATABROKER, "0", tm0},
			{registry.ServiceKind_DATABROKER, "2", tm0},
			{registry.ServiceKind_DATABROKER, "4", tm0},
			{registry.ServiceKind_DATABROKER, "6", tm0},
			{registry.ServiceKind_DATABROKER, "8", tm0},
			{registry.ServiceKind_AUTHORIZE, "1", tm0},
			{registry.ServiceKind_AUTHORIZE, "3", tm0},
			{registry.ServiceKind_AUTHORIZE, "5", tm0},
			{registry.ServiceKind_AUTHORIZE, "7", tm0},
			{registry.ServiceKind_AUTHORIZE, "9", tm0},
		}, nodes)

		for i := range 10 {
			assert.NoError(t, registryServiceKeySpace.delete(db, registry.ServiceKind(i%2+1), fmt.Sprintf("%d", i)))
		}

		assert.Empty(t, dumpDatabase(t, db))

		nodes, err = iterutil.CollectWithError(registryServiceKeySpace.iterate(db))
		assert.NoError(t, err)
		assert.Empty(t, nodes)
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
