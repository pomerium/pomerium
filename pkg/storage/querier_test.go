package storage_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestGetDataBrokerRecord(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	for _, tc := range []struct {
		name                                   string
		recordVersion, queryVersion            uint64
		underlyingQueryCount, cachedQueryCount int
	}{
		{"cached", 1, 1, 1, 2},
		{"invalidated", 1, 2, 3, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s1 := &session.Session{Id: "s1", Version: fmt.Sprint(tc.recordVersion)}

			sq := storage.NewStaticQuerier(s1)
			cq := storage.NewCachingQuerier(sq, storage.NewGlobalCache(time.Minute))
			qctx := storage.WithQuerier(ctx, cq)

			s, err := storage.GetDataBrokerRecord(qctx, grpcutil.GetTypeURL(s1), s1.GetId(), tc.queryVersion)
			assert.NoError(t, err)
			assert.NotNil(t, s)

			s, err = storage.GetDataBrokerRecord(qctx, grpcutil.GetTypeURL(s1), s1.GetId(), tc.queryVersion)
			assert.NoError(t, err)
			assert.NotNil(t, s)
		})
	}
}

func TestGetDataBrokerMessage(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	s1 := &session.Session{Id: "s1"}
	sq := storage.NewStaticQuerier(s1)
	cq := storage.NewCachingQuerier(sq, storage.NewGlobalCache(time.Minute))
	qctx := storage.WithQuerier(ctx, cq)

	s2, err := storage.GetDataBrokerMessage[session.Session](qctx, "s1", 0)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(s1, s2, protocmp.Transform()))

	_, err = storage.GetDataBrokerMessage[session.Session](qctx, "s2", 0)
	assert.ErrorIs(t, err, databroker.ErrRecordNotFound)
}

func TestGetDataBrokerObjectViaJSON(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	du1 := &directory.User{
		ID:          "u1",
		Email:       "u1@example.com",
		DisplayName: "User 1!",
	}
	sq := storage.NewStaticQuerier(newDirectoryUserRecord(du1))
	cq := storage.NewCachingQuerier(sq, storage.NewGlobalCache(time.Minute))
	qctx := storage.WithQuerier(ctx, cq)

	du2, err := storage.GetDataBrokerObjectViaJSON[directory.User](qctx, directory.UserRecordType, "u1", 0)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(du1, du2, protocmp.Transform()))
}

func newDirectoryUserRecord(directoryUser *directory.User) *databroker.Record {
	m := map[string]any{}
	bs, _ := json.Marshal(directoryUser)
	_ = json.Unmarshal(bs, &m)
	s, _ := structpb.NewStruct(m)
	return storage.NewStaticRecord(directory.UserRecordType, s)
}
