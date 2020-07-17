package databroker

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestConfigSource(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	db := New()
	srv := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(srv, db)
	go func() { _ = srv.Serve(li) }()

	cfgs := make(chan *config.Config, 10)

	src := NewConfigSource(config.NewStaticSource(&config.Config{
		Options: &config.Options{
			DataBrokerURL: mustParse("http://" + li.Addr().String()),
			GRPCInsecure:  true,
		},
	}), func(cfg *config.Config) {
		cfgs <- cfg
	})
	cfgs <- src.GetConfig()

	data, _ := ptypes.MarshalAny(&configpb.Config{
		Name: "config",
		Policies: []*configpb.Policy{
			{
				From: "https://from.example.com",
				To:   "https://to.example.com",
			},
		},
	})
	_, _ = db.Set(ctx, &databroker.SetRequest{
		Type: configTypeURL,
		Id:   "1",
		Data: data,
	})

	select {
	case <-ctx.Done():
		assert.NoError(t, ctx.Err())
		return
	case cfg := <-cfgs:
		assert.Len(t, cfg.Options.Policies, 0)
	}

	select {
	case <-ctx.Done():
		assert.NoError(t, ctx.Err())
		return
	case cfg := <-cfgs:
		assert.Len(t, cfg.Options.Policies, 1)
	}
}

func mustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
