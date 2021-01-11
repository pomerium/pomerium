package grpcutil

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestSignedJWT(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	li, err := net.Listen("tcp4", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	key := cryptutil.NewKey()
	srv := grpc.NewServer(
		grpc.StreamInterceptor(StreamRequireSignedJWT(base64.StdEncoding.EncodeToString(key))),
		grpc.UnaryInterceptor(UnaryRequireSignedJWT(base64.StdEncoding.EncodeToString(key))),
	)
	reflection.Register(srv)
	go srv.Serve(li)

	t.Run("unauthenticated", func(t *testing.T) {
		cc, err := grpc.Dial(li.Addr().String(),
			grpc.WithInsecure())
		if !assert.NoError(t, err) {
			return
		}
		defer cc.Close()

		client := grpc_reflection_v1alpha.NewServerReflectionClient(cc)
		stream, err := client.ServerReflectionInfo(ctx, grpc.WaitForReady(true))
		if !assert.NoError(t, err) {
			return
		}

		err = stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
			Host:           "",
			MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{},
		})
		if !assert.NoError(t, err) {
			return
		}

		_, err = stream.Recv()
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
	t.Run("authenticated", func(t *testing.T) {
		cc, err := grpc.Dial(li.Addr().String(),
			grpc.WithUnaryInterceptor(WithUnarySignedJWT(key)),
			grpc.WithStreamInterceptor(WithStreamSignedJWT(key)),
			grpc.WithInsecure())
		if !assert.NoError(t, err) {
			return
		}
		defer cc.Close()

		client := grpc_reflection_v1alpha.NewServerReflectionClient(cc)
		stream, err := client.ServerReflectionInfo(ctx, grpc.WaitForReady(true))
		if !assert.NoError(t, err) {
			return
		}

		err = stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
			Host:           "",
			MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{},
		})
		if !assert.NoError(t, err) {
			return
		}

		_, err = stream.Recv()
		assert.Equal(t, codes.OK, status.Code(err))
	})
}
