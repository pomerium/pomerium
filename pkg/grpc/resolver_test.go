package grpc

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/grpc_testing"
)

type resolverTestServer struct {
	grpc_testing.UnimplementedTestServiceServer
	username string
}

func (srv *resolverTestServer) UnaryCall(context.Context, *grpc_testing.SimpleRequest) (*grpc_testing.SimpleResponse, error) {
	return &grpc_testing.SimpleResponse{
		Username: srv.username,
	}, nil
}

func TestResolver(t *testing.T) {
	li1, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = li1.Close() }()

	srv1 := grpc.NewServer()
	grpc_testing.RegisterTestServiceServer(srv1, &resolverTestServer{
		username: "srv1",
	})
	go func() { _ = srv1.Serve(li1) }()

	li2, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = li2.Close() }()

	srv2 := grpc.NewServer()
	grpc_testing.RegisterTestServiceServer(srv2, &resolverTestServer{
		username: "srv2",
	})
	go func() { _ = srv2.Serve(li2) }()

	cc, err := grpc.Dial("pomerium:///"+strings.Join([]string{
		li1.Addr().String(),
		li2.Addr().String(),
	}, ","), grpc.WithInsecure(), grpc.WithDefaultServiceConfig(roundRobinServiceConfig))
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = cc.Close() }()

	c := grpc_testing.NewTestServiceClient(cc)
	usernames := map[string]int{}
	for i := 0; i < 1000; i++ {
		res, err := c.UnaryCall(context.Background(), new(grpc_testing.SimpleRequest))
		assert.NoError(t, err)
		usernames[res.GetUsername()]++
	}
	assert.Equal(t, 500, usernames["srv1"])
	assert.Equal(t, 500, usernames["srv2"])

}
