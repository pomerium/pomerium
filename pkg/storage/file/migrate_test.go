package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/pebbleutil"
)

func TestMigrate(t *testing.T) {
	t.Parallel()

	db := pebbleutil.MustOpenMemory(nil)
	require.NoError(t, migrate(db))
	kvs := dumpDatabase(t, db)
	if assert.Len(t, kvs, 4) {
		assert.Equal(t, []byte{0x02, 0x01}, kvs[0][0],
			"should set server version")
		if serverVersion, err := decodeUint64(kvs[0][1]); assert.NoError(t, err) {
			assert.Greater(t, serverVersion, uint64(0),
				"should set server version to non-zero uint64")
		}
		assert.Equal(t, [2][]byte{{0x02, 0x02}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}}, kvs[1],
			"should set migration")
		assert.Equal(t, []byte{0x02, 0x03}, kvs[2][0],
			"should set checkpoint server version")
		if checkpointServerVersion, err := decodeUint64(kvs[2][1]); assert.NoError(t, err) {
			assert.Equal(t, checkpointServerVersion, uint64(0),
				"should set checkpoint server version to zero")
		}
		assert.Equal(t, []byte{0x02, 0x04}, kvs[3][0],
			"should set checkpoint record version")
		if checkpointRecordVersion, err := decodeUint64(kvs[3][1]); assert.NoError(t, err) {
			assert.Equal(t, checkpointRecordVersion, uint64(0),
				"should set checkpoint record version to zero")
		}
	}
}
