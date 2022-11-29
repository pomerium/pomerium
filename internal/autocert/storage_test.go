package autocert

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = li.Close() }()

	srv := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv, databroker.New())
	go func() { _ = srv.Serve(li) }()

	cc, err := grpc.Dial(li.Addr().String(), grpc.WithInsecure())
	require.NoError(t, err)

	s := newDataBrokerStorage(atomicutil.NewValue(databrokerpb.NewDataBrokerServiceClient(cc)))

	assert.False(t, s.Exists(ctx, "example/1"))

	for _, r := range []struct {
		key   string
		value []byte
	}{
		{"example/1", []byte{1, 2, 3}},
		{"example/2", []byte{4, 5, 6}},
		{"example/3", []byte{7, 8, 9}},
		{"example/3/1", []byte{11, 12, 13}},
		{"example/3/2", []byte{14, 15, 16}},
		{"example/3/3", []byte{17, 18, 19}},
	} {
		assert.NoError(t, s.Store(ctx, r.key, r.value))
		assert.True(t, s.Exists(ctx, r.key))
		v, err := s.Load(ctx, r.key)
		assert.NoError(t, err)
		assert.Equal(t, r.value, v)

		fi, err := s.Stat(ctx, r.key)
		assert.NoError(t, err)
		assert.Equal(t, r.key, fi.Key)
		assert.True(t, fi.IsTerminal)
		assert.NotZero(t, fi.Modified)
		assert.Equal(t, int64(len(r.value)), fi.Size)
	}

	keys, err := s.List(ctx, "example/3", true)
	assert.NoError(t, err)
	assert.Equal(t, []string{"example/3", "example/3/1", "example/3/2", "example/3/3"}, keys)

	keys, err = s.List(ctx, "example/3", false)
	assert.NoError(t, err)
	assert.Equal(t, []string{"example/3"}, keys)

	assert.NoError(t, s.Delete(ctx, "example/3/2"))

	keys, err = s.List(ctx, "example/3", true)
	assert.NoError(t, err)
	assert.Equal(t, []string{"example/3", "example/3/1", "example/3/3"}, keys)
}

func TestStorageLocker(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = li.Close() }()

	srv := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv, databroker.New())
	go func() { _ = srv.Serve(li) }()

	cc, err := grpc.Dial(li.Addr().String(), grpc.WithInsecure())
	require.NoError(t, err)

	s := newDataBrokerStorage(atomicutil.NewValue(databrokerpb.NewDataBrokerServiceClient(cc)))

	err = s.Lock(ctx, "example")
	assert.NoError(t, err)

	err = s.Unlock(ctx, "example")
	assert.NoError(t, err)
}
