package databroker

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	internalSrv := internal_databroker.New(context.Background())
	srv := &dataBrokerServer{server: internalSrv}
	srv.sharedKey.Store([]byte{})
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
	any, _ := ptypes.MarshalAny(new(user.User))
	numRecords := 200

	var serverVersion uint64

	for i := 0; i < numRecords; i++ {
		res, err := c.Put(ctx, &databroker.PutRequest{
			Record: &databroker.Record{
				Type: any.TypeUrl,
				Id:   strconv.Itoa(i),
				Data: any,
			},
		})
		require.NoError(t, err)
		serverVersion = res.GetServerVersion()
	}

	t.Run("Sync ok", func(t *testing.T) {
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
		require.Equal(t, codes.Aborted, status.Code(err))
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
	any, _ := ptypes.MarshalAny(new(session.Session))
	numRecords := 10000

	for i := 0; i < numRecords; i++ {
		_, _ = c.Put(ctx, &databroker.PutRequest{
			Record: &databroker.Record{
				Type: any.TypeUrl,
				Id:   strconv.Itoa(i),
				Data: any,
			},
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
