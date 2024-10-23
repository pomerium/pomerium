package authorize

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func Test_getDataBrokerRecord(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	for _, tc := range []struct {
		name                                   string
		recordVersion, queryVersion            uint64
		underlyingQueryCount, cachedQueryCount int
	}{
		{"cached", 1, 1, 1, 2},
		{"invalidated", 1, 2, 3, 4},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s1 := &session.Session{Id: "s1", Version: fmt.Sprint(tc.recordVersion)}

			sq := storage.NewStaticQuerier(s1)
			tsq := storage.NewTracingQuerier(sq)
			cq := storage.NewCachingQuerier(tsq, storage.NewLocalCache())
			tcq := storage.NewTracingQuerier(cq)
			qctx := storage.WithQuerier(ctx, tcq)

			s, err := getDataBrokerRecord(qctx, grpcutil.GetTypeURL(s1), s1.GetId(), tc.queryVersion)
			assert.NoError(t, err)
			assert.NotNil(t, s)

			s, err = getDataBrokerRecord(qctx, grpcutil.GetTypeURL(s1), s1.GetId(), tc.queryVersion)
			assert.NoError(t, err)
			assert.NotNil(t, s)

			assert.Len(t, tsq.Traces(), tc.underlyingQueryCount,
				"should have %d traces to the underlying querier", tc.underlyingQueryCount)
			assert.Len(t, tcq.Traces(), tc.cachedQueryCount,
				"should have %d traces to the cached querier", tc.cachedQueryCount)
		})
	}
}

func TestAuthorize_getDataBrokerSessionOrServiceAccount(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	opt := config.NewDefaultOptions()
	a, err := New(context.Background(), &config.Config{Options: opt})
	require.NoError(t, err)

	s1 := &session.Session{Id: "s1", ExpiresAt: timestamppb.New(time.Now().Add(-time.Second))}
	sq := storage.NewStaticQuerier(s1)
	qctx := storage.WithQuerier(ctx, sq)
	_, err = a.getDataBrokerSessionOrServiceAccount(qctx, "s1", 0)
	assert.ErrorIs(t, err, session.ErrSessionExpired)
}
