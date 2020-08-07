package cache

import (
	"context"
	"log"
	"net"
	"strconv"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	internalSrv := internal_databroker.New()
	srv := &DataBrokerServer{DataBrokerServiceServer: internalSrv}
	databroker.RegisterDataBrokerServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
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

	for i := 0; i < 10000; i++ {
		c.Set(ctx, &databroker.SetRequest{Type: any.TypeUrl, Id: strconv.Itoa(i), Data: any})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, _ := c.Sync(ctx, &databroker.SyncRequest{Type: any.GetTypeUrl()})
		count := 0
		for {
			res, err := client.Recv()
			if err != nil {
				break
			}
			count += len(res.Records)
			if count == 10000 {
				break
			}
		}
	}

}
