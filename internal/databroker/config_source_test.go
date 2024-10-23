package databroker

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestConfigSource(t *testing.T) {
	t.Parallel()

	generateCert := func(name string) ([]byte, []byte) {
		cert, err := cryptutil.GenerateCertificate(nil, name)
		require.NoError(t, err)
		certPEM, keyPEM, err := cryptutil.EncodeCertificate(cert)
		require.NoError(t, err)
		return certPEM, keyPEM
	}

	ctx, clearTimeout := context.WithTimeout(context.Background(), 50*time.Second)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = li.Close() }()
	_, outboundPort, _ := net.SplitHostPort(li.Addr().String())

	dataBrokerServer := New(ctx)
	srv := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(srv, dataBrokerServer)
	go func() { _ = srv.Serve(li) }()

	cfgs := make(chan *config.Config, 10)

	u, _ := url.Parse("https://to.example.com")
	base := config.NewDefaultOptions()
	base.DataBrokerURLString = "http://" + li.Addr().String()
	base.InsecureServer = true
	base.GRPCInsecure = proto.Bool(true)
	base.Policies = append(base.Policies, config.Policy{
		From: "https://pomerium.io", To: config.WeightedURLs{
			{URL: *u},
		}, AllowedUsers: []string{"foo@bar.com"},
	})
	certPEM, keyPEM := generateCert("*.example.com")
	base.Cert, base.Key = base64.StdEncoding.EncodeToString(certPEM), base64.StdEncoding.EncodeToString(keyPEM)

	baseSource := config.NewStaticSource(&config.Config{
		OutboundPort: outboundPort,
		Options:      base,
	})
	src := NewConfigSource(ctx, baseSource, EnableConfigValidation(true), func(_ context.Context, cfg *config.Config) {
		cfgs <- cfg
	})
	cfgs <- src.GetConfig()

	route := &configpb.Route{
		From: "https://from.example.com",
		To:   []string{"https://to.example.com"},
	}
	cert := &configpb.Settings_Certificate{}
	cert.CertBytes, cert.KeyBytes = generateCert("*.example.com")
	data := protoutil.NewAny(&configpb.Config{
		Name:   "config",
		Routes: []*configpb.Route{route},
		Settings: &configpb.Settings{
			Certificates: []*configpb.Settings_Certificate{cert},
		},
	})
	_, _ = dataBrokerServer.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.TypeUrl,
			Id:   "1",
			Data: data,
		}},
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
		assert.Len(t, cfg.Options.CertificateFiles, 0, "ignores overlapping certificate")
	}

	baseSource.SetConfig(ctx, &config.Config{
		OutboundPort: outboundPort,
		Options:      base,
	})
}
