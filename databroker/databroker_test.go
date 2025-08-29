package databroker_test

import (
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		opts    config.Options
		wantErr bool
	}{
		{"good", config.Options{SharedKey: cryptutil.NewBase64Key(), DataBrokerURLString: "http://example"}, false},
		{"bad shared secret", config.Options{SharedKey: string([]byte(cryptutil.NewBase64Key())[:31]), DataBrokerURLString: "http://example"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Provider = "google"
			_, err := databroker.New(t.Context(), &config.Config{Options: &tt.opts}, events.New())
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestServerSync(t *testing.T) {
	sharedKey := cryptutil.NewKey()
	srv := databroker.NewServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(sharedKey),
		},
	})

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
	c := databrokerpb.NewDataBrokerServiceClient(cc)
	ctx, err := grpcutil.WithSignedJWT(t.Context(), sharedKey)
	require.NoError(t, err)

	data := protoutil.NewAny(new(user.User))
	numRecords := 200

	var serverVersion uint64

	for i := 0; i < numRecords; i++ {
		res, err := c.Put(ctx, &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type: data.TypeUrl,
				Id:   strconv.Itoa(i),
				Data: data,
			}},
		})
		require.NoError(t, err)
		serverVersion = res.GetServerVersion()
	}

	t.Run("Sync ok", func(_ *testing.T) {
		client, _ := c.Sync(ctx, &databrokerpb.SyncRequest{
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
		client, err := c.Sync(ctx, &databrokerpb.SyncRequest{
			ServerVersion: 0,
		})
		require.NoError(t, err)
		_, err = client.Recv()
		assert.ErrorIs(t, err, databrokerpb.ErrInvalidServerVersion)
	})
}

func BenchmarkSync(b *testing.B) {
	sharedKey := cryptutil.NewKey()
	srv := databroker.NewServer(noop.NewTracerProvider())
	b.Cleanup(srv.Stop)
	srv.OnConfigChange(b.Context(), &config.Config{
		Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(sharedKey),
		},
	})

	cc := testutil.NewGRPCServer(b, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
	c := databrokerpb.NewDataBrokerServiceClient(cc)
	ctx, err := grpcutil.WithSignedJWT(b.Context(), sharedKey)
	require.NoError(b, err)

	data := protoutil.NewAny(new(session.Session))
	numRecords := 10000

	for i := range numRecords {
		_, _ = c.Put(ctx, &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type: data.TypeUrl,
				Id:   strconv.Itoa(i),
				Data: data,
			}},
		})
	}

	b.ResetTimer()
	for b.Loop() {
		client, _ := c.Sync(ctx, &databrokerpb.SyncRequest{})
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
