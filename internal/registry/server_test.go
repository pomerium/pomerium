package registry

import (
	"context"
	"net"
	"testing"

	pb "github.com/pomerium/pomerium/pkg/grpc/registry"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestRegistry(t *testing.T) {
	l := bufconn.Listen(1024)
	defer l.Close()

	dialer := func(context.Context, string) (net.Conn, error) {
		return l.Dial()
	}

	gs := grpc.NewServer()
	pb.RegisterRegistryServer(gs, &inMemoryServer{})

	go func() {
		err := gs.Serve(l)
		assert.NoError(t, err)
	}()

	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "inmem", grpc.WithContextDialer(dialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := pb.NewRegistryClient(conn)

	registerTC := []struct {
		svc         []*pb.Service
		expectError bool
	}{
		{[]*pb.Service{{Endpoint: []string{"http://localhost"}}}, true},
	}

	for _, tc := range registerTC {
		_, err := client.Report(ctx, &pb.RegisterRequest{
			Service: tc.svc,
		})
		if tc.expectError {
			assert.Error(t, err, "%v", tc)
		} else {
			assert.NoError(t, err, "%v", tc)
		}
	}
}
