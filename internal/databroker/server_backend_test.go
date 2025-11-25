package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type testSyncerHandler struct {
	getDataBrokerServiceClient func() databrokerpb.DataBrokerServiceClient
	clearRecords               func(ctx context.Context)
	updateRecords              func(ctx context.Context, serverVersion uint64, records []*databrokerpb.Record)
}

func (h testSyncerHandler) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return h.getDataBrokerServiceClient()
}

func (h testSyncerHandler) ClearRecords(ctx context.Context) {
	h.clearRecords(ctx)
}

func (h testSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databrokerpb.Record) {
	h.updateRecords(ctx, serverVersion, records)
}

func newServer(tb testing.TB) Server {
	tb.Helper()

	srv := NewBackendServer(noop.NewTracerProvider())
	tb.Cleanup(srv.Stop)
	srv.OnConfigChange(tb.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
			SharedKey:  cryptutil.NewBase64Key(),
		},
	})
	return srv
}

func TestServer_Get(t *testing.T) {
	t.Parallel()

	t.Run("ignore deleted", func(t *testing.T) {
		srv := newServer(t)

		s := new(sessionpb.Session)
		s.Id = "1"
		data := protoutil.NewAny(s)
		_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)
		_, err = srv.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type:      data.TypeUrl,
				Id:        s.Id,
				DeletedAt: timestamppb.Now(),
			}},
		})
		assert.NoError(t, err)
		_, err = srv.Get(t.Context(), &databrokerpb.GetRequest{
			Type: data.TypeUrl,
			Id:   s.Id,
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestServer_Patch(t *testing.T) {
	t.Parallel()

	srv := newServer(t)

	s := &sessionpb.Session{
		Id:         "1",
		OauthToken: &sessionpb.OAuthToken{AccessToken: "access-token"},
	}
	data := protoutil.NewAny(s)
	_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	require.NoError(t, err)

	fm, err := fieldmaskpb.New(s, "accessed_at")
	require.NoError(t, err)

	now := timestamppb.Now()
	s.AccessedAt = now
	s.OauthToken.AccessToken = "access-token-field-ignored"
	data = protoutil.NewAny(s)
	patchResponse, err := srv.Patch(t.Context(), &databrokerpb.PatchRequest{
		Records: []*databrokerpb.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
		FieldMask: fm,
	})
	require.NoError(t, err)
	testutil.AssertProtoEqual(t, protoutil.NewAny(&sessionpb.Session{
		Id:         "1",
		AccessedAt: now,
		OauthToken: &sessionpb.OAuthToken{AccessToken: "access-token"},
	}), patchResponse.GetRecord().GetData())

	getResponse, err := srv.Get(t.Context(), &databrokerpb.GetRequest{
		Type: data.TypeUrl,
		Id:   s.Id,
	})
	require.NoError(t, err)
	testutil.AssertProtoEqual(t, protoutil.NewAny(&sessionpb.Session{
		Id:         "1",
		AccessedAt: now,
		OauthToken: &sessionpb.OAuthToken{AccessToken: "access-token"},
	}), getResponse.GetRecord().GetData())
}

func TestServer_Options(t *testing.T) {
	t.Parallel()

	srv := newServer(t)

	s := new(sessionpb.Session)
	s.Id = "1"
	data := protoutil.NewAny(s)
	_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	assert.NoError(t, err)
	_, err = srv.SetOptions(t.Context(), &databrokerpb.SetOptionsRequest{
		Type: data.TypeUrl,
		Options: &databrokerpb.Options{
			Capacity: proto.Uint64(1),
		},
	})
	assert.NoError(t, err)

	_, err = srv.GetOptions(t.Context(), &databrokerpb.GetOptionsRequest{
		Type: "",
	})

	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	opts, err := srv.GetOptions(t.Context(), &databrokerpb.GetOptionsRequest{
		Type: data.TypeUrl,
	})
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), opts.Options.GetCapacity())

	_, err = srv.GetOptions(t.Context(), &databrokerpb.GetOptionsRequest{
		Type: "foo",
	})
	assert.Error(t, err)
	st, ok = status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestServer_Lease(t *testing.T) {
	t.Parallel()

	srv := newServer(t)

	res, err := srv.AcquireLease(t.Context(), &databrokerpb.AcquireLeaseRequest{
		Name:     "TEST",
		Duration: durationpb.New(time.Second * 10),
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, res.GetId())

	_, err = srv.RenewLease(t.Context(), &databrokerpb.RenewLeaseRequest{
		Name:     "TEST",
		Id:       res.GetId(),
		Duration: durationpb.New(time.Second * 10),
	})
	assert.NoError(t, err)

	_, err = srv.ReleaseLease(t.Context(), &databrokerpb.ReleaseLeaseRequest{
		Name: "TEST",
		Id:   res.GetId(),
	})
	assert.NoError(t, err)
}

func TestServer_Query(t *testing.T) {
	t.Parallel()

	srv := newServer(t)

	for i := 0; i < 10; i++ {
		s := new(sessionpb.Session)
		s.Id = fmt.Sprint(i)
		data := protoutil.NewAny(s)
		_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)
	}
	res, err := srv.Query(t.Context(), &databrokerpb.QueryRequest{
		Type: protoutil.GetTypeURL(new(sessionpb.Session)),
		Filter: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"$or": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
					structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
						"id": structpb.NewStringValue("1"),
					}}),
					structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
						"id": structpb.NewStringValue("3"),
					}}),
					structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
						"id": structpb.NewStringValue("5"),
					}}),
					structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
						"id": structpb.NewStringValue("7"),
					}}),
				}}),
			},
		},
		Limit: 10,
	})
	assert.NoError(t, err)

	if assert.Len(t, res.Records, 4) {
		sort.Slice(res.Records, func(i, j int) bool {
			return res.Records[i].GetId() < res.Records[j].GetId()
		})
		assert.Equal(t, "1", res.Records[0].GetId())
		assert.Equal(t, "3", res.Records[1].GetId())
		assert.Equal(t, "5", res.Records[2].GetId())
		assert.Equal(t, "7", res.Records[3].GetId())
	}
}

func TestServer_Sync(t *testing.T) {
	t.Parallel()

	srv := newServer(t)

	s := new(sessionpb.Session)
	s.Id = "1"
	data := protoutil.NewAny(s)
	_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	assert.NoError(t, err)

	gs := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(gs, srv)
	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer li.Close()

	eg, ctx := errgroup.WithContext(t.Context())
	eg.Go(func() error {
		return gs.Serve(li)
	})
	eg.Go(func() error {
		defer gs.Stop()

		cc, err := grpc.DialContext(ctx, li.Addr().String(), grpc.WithInsecure())
		if err != nil {
			return err
		}
		defer cc.Close()

		clearRecords := make(chan struct{}, 10)
		updateRecords := make(chan uint64, 10)

		client := databrokerpb.NewDataBrokerServiceClient(cc)
		syncer := databrokerpb.NewSyncer(ctx, "TEST", testSyncerHandler{
			getDataBrokerServiceClient: func() databrokerpb.DataBrokerServiceClient {
				return client
			},
			clearRecords: func(_ context.Context) {
				clearRecords <- struct{}{}
			},
			updateRecords: func(_ context.Context, recordVersion uint64, _ []*databrokerpb.Record) {
				updateRecords <- recordVersion
			},
		})
		go syncer.Run(ctx)
		select {
		case <-clearRecords:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		select {
		case <-updateRecords:
		case <-ctx.Done():
			return context.Cause(ctx)

		}

		_, err = srv.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)

		select {
		case <-updateRecords:
		case <-ctx.Done():
			return context.Cause(ctx)

		}
		return nil
	})
	assert.NoError(t, eg.Wait())
}

func TestServerInvalidStorage(t *testing.T) {
	t.Parallel()

	srv := newServer(t)
	srv.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			DataBroker: config.DataBrokerOptions{StorageType: "<INVALID>"},
		},
	})

	s := new(sessionpb.Session)
	s.Id = "1"
	data := protoutil.NewAny(s)
	_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	_ = assert.Error(t, err) && assert.Contains(t, err.Error(), "unsupported storage type")
}

func TestServerPostgres(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(t, func(dsn string) {
		srv := newServer(t)
		srv.OnConfigChange(t.Context(), &config.Config{
			Options: &config.Options{
				DataBroker: config.DataBrokerOptions{
					StorageType:             "postgres",
					StorageConnectionString: dsn,
				},
			},
		})

		s := new(sessionpb.Session)
		s.Id = "1"
		data := protoutil.NewAny(s)
		_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)

		gs := grpc.NewServer()
		databrokerpb.RegisterDataBrokerServiceServer(gs, srv)
		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer li.Close()

		eg, ctx := errgroup.WithContext(t.Context())
		eg.Go(func() error {
			return gs.Serve(li)
		})
		eg.Go(func() error {
			defer gs.Stop()

			cc, err := grpc.DialContext(ctx, li.Addr().String(), grpc.WithInsecure())
			if err != nil {
				return err
			}
			defer cc.Close()

			client := databrokerpb.NewDataBrokerServiceClient(cc)
			stream, err := client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{
				Type: data.TypeUrl,
			})
			if err != nil {
				return err
			}

			for {
				res, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					return err
				}

				assert.NotNil(t, res)
			}

			return nil
		})
		assert.NoError(t, eg.Wait())
	})
}
