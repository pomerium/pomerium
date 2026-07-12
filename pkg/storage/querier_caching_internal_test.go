package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestCachingQuerierGetCacheKey(t *testing.T) {
	t.Parallel()

	q := new(cachingQuerier)
	withoutHint := &databroker.QueryRequest{
		Type:  "type.googleapis.com/example.Record",
		Limit: 1,
	}
	withoutHint.SetFilterByIDOrIndex("record-1")

	withoutHintBefore := proto.Clone(withoutHint).(*databroker.QueryRequest)
	want, err := MarshalQueryRequest(withoutHint)
	require.NoError(t, err)
	got, err := q.getCacheKey(withoutHint)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got))
	require.True(t, proto.Equal(withoutHintBefore, withoutHint), "request without hint was mutated")

	withHint := proto.Clone(withoutHint).(*databroker.QueryRequest)
	withHint.MinimumRecordVersionHint = proto.Uint64(42)
	withHintBefore := proto.Clone(withHint).(*databroker.QueryRequest)
	got, err = q.getCacheKey(withHint)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got), "minimum record version hint changed the cache key")
	require.True(t, proto.Equal(withHintBefore, withHint), "request with hint was mutated")
}
