package databroker

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/atomicutil"
	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	internalSrv := internal_databroker.New(context.Background(), trace.NewNoopTracerProvider())
	srv := &dataBrokerServer{server: internalSrv, sharedKey: atomicutil.NewValue([]byte{})}
	databroker.RegisterDataBrokerServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("Server exited with error")
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestServerSync(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	require.NoError(t, err)
	defer conn.Close()
	c := databroker.NewDataBrokerServiceClient(conn)
	data := protoutil.NewAny(new(user.User))
	numRecords := 200

	var serverVersion uint64

	for i := 0; i < numRecords; i++ {
		res, err := c.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: data.TypeUrl,
				Id:   strconv.Itoa(i),
				Data: data,
			}},
		})
		require.NoError(t, err)
		serverVersion = res.GetServerVersion()
	}

	t.Run("Sync ok", func(_ *testing.T) {
		client, _ := c.Sync(ctx, &databroker.SyncRequest{
			ServerVersion: serverVersion,
		})
		count := 0
		for {
			_, err := client.Recv()
			if err != nil {
				break
			}
			count++
			if count == numRecords {
				break
			}
		}
	})
	t.Run("Aborted", func(t *testing.T) {
		client, err := c.Sync(ctx, &databroker.SyncRequest{
			ServerVersion: 0,
		})
		require.NoError(t, err)
		_, err = client.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Aborted.String(), status.Code(err).String())
	})
}

func BenchmarkSync(b *testing.B) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		b.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	c := databroker.NewDataBrokerServiceClient(conn)
	data := protoutil.NewAny(new(session.Session))
	numRecords := 10000

	for i := 0; i < numRecords; i++ {
		_, _ = c.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: data.TypeUrl,
				Id:   strconv.Itoa(i),
				Data: data,
			}},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, _ := c.Sync(ctx, &databroker.SyncRequest{})
		count := 0
		for {
			_, err := client.Recv()
			if err != nil {
				break
			}
			count++
			if count == numRecords {
				break
			}
		}
	}
}
