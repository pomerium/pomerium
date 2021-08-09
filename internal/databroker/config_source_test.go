package databroker

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestConfigSource(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = li.Close() }()

	dataBrokerServer := New()
	srv := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(srv, dataBrokerServer)
	go func() { _ = srv.Serve(li) }()

	cfgs := make(chan *config.Config, 10)

	u, _ := url.Parse("https://to.example.com")
	base := config.NewDefaultOptions()
	base.DataBrokerURLString = "http://" + li.Addr().String()
	base.InsecureServer = true
	base.GRPCInsecure = true
	base.Policies = append(base.Policies, config.Policy{
		From: "https://pomerium.io", To: config.WeightedURLs{
			{URL: *u},
		}, AllowedUsers: []string{"foo@bar.com"},
	})

	baseSource := config.NewStaticSource(&config.Config{
		Options: base,
	})
	src := NewConfigSource(ctx, baseSource, func(_ context.Context, cfg *config.Config) {
		cfgs <- cfg
	})
	cfgs <- src.GetConfig()

	data := protoutil.NewAny(&configpb.Config{
		Name: "config",
		Routes: []*configpb.Route{
			{
				From: "https://from.example.com",
				To:   []string{"https://to.example.com"},
			},
		},
	})
	_, _ = dataBrokerServer.Put(ctx, &databroker.PutRequest{
		Record: &databroker.Record{
			Type: data.TypeUrl,
			Id:   "1",
			Data: data,
		},
	})

	select {
	case <-ctx.Done():
		assert.NoError(t, ctx.Err())
		return
	case cfg := <-cfgs:
		assert.Len(t, cfg.Options.AdditionalPolicies, 0)
	}

	select {
	case <-ctx.Done():
		assert.NoError(t, ctx.Err())
		return
	case cfg := <-cfgs:
		assert.Len(t, cfg.Options.AdditionalPolicies, 1)
	}

	baseSource.SetConfig(ctx, &config.Config{
		Options: base,
	})
}
