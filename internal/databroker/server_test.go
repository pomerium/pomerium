package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type testSyncerHandler struct {
	getDataBrokerServiceClient func() databroker.DataBrokerServiceClient
	clearRecords               func(ctx context.Context)
	updateRecords              func(ctx context.Context, serverVersion uint64, records []*databroker.Record)
}

func (h testSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return h.getDataBrokerServiceClient()
}

func (h testSyncerHandler) ClearRecords(ctx context.Context) {
	h.clearRecords(ctx)
}

func (h testSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	h.updateRecords(ctx, serverVersion, records)
}

func newServer(cfg *serverConfig) *Server {
	return &Server{
		cfg: cfg,
	}
}

func TestServer_Get(t *testing.T) {
	cfg := newServerConfig()
	t.Run("ignore deleted", func(t *testing.T) {
		srv := newServer(cfg)

		s := new(session.Session)
		s.Id = "1"
		data := protoutil.NewAny(s)
		_, err := srv.Put(context.Background(), &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)
		_, err = srv.Put(context.Background(), &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type:      data.TypeUrl,
				Id:        s.Id,
				DeletedAt: timestamppb.Now(),
			}},
		})
		assert.NoError(t, err)
		_, err = srv.Get(context.Background(), &databroker.GetRequest{
			Type: data.TypeUrl,
			Id:   s.Id,
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestServer_Patch(t *testing.T) {
	cfg := newServerConfig()
	srv := newServer(cfg)

	s := &session.Session{
		Id:         "1",
		OauthToken: &session.OAuthToken{AccessToken: "access-token"},
	}
	data := protoutil.NewAny(s)
	_, err := srv.Put(context.Background(), &databroker.PutRequest{
		Records: []*databroker.Record{{
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
	patchResponse, err := srv.Patch(context.Background(), &databroker.PatchRequest{
		Records: []*databroker.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
		FieldMask: fm,
	})
	require.NoError(t, err)
	testutil.AssertProtoEqual(t, protoutil.NewAny(&session.Session{
		Id:         "1",
		AccessedAt: now,
		OauthToken: &session.OAuthToken{AccessToken: "access-token"},
	}), patchResponse.GetRecord().GetData())

	getResponse, err := srv.Get(context.Background(), &databroker.GetRequest{
		Type: data.TypeUrl,
		Id:   s.Id,
	})
	require.NoError(t, err)
	testutil.AssertProtoEqual(t, protoutil.NewAny(&session.Session{
		Id:         "1",
		AccessedAt: now,
		OauthToken: &session.OAuthToken{AccessToken: "access-token"},
	}), getResponse.GetRecord().GetData())
}

func TestServer_Options(t *testing.T) {
	cfg := newServerConfig()
	srv := newServer(cfg)

	s := new(session.Session)
	s.Id = "1"
	data := protoutil.NewAny(s)
	_, err := srv.Put(context.Background(), &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	assert.NoError(t, err)
	_, err = srv.SetOptions(context.Background(), &databroker.SetOptionsRequest{
		Type: data.TypeUrl,
		Options: &databroker.Options{
			Capacity: proto.Uint64(1),
		},
	})
	assert.NoError(t, err)
}

func TestServer_Lease(t *testing.T) {
	cfg := newServerConfig()
	srv := newServer(cfg)

	res, err := srv.AcquireLease(context.Background(), &databroker.AcquireLeaseRequest{
		Name:     "TEST",
		Duration: durationpb.New(time.Second * 10),
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, res.GetId())

	_, err = srv.RenewLease(context.Background(), &databroker.RenewLeaseRequest{
		Name:     "TEST",
		Id:       res.GetId(),
		Duration: durationpb.New(time.Second * 10),
	})
	assert.NoError(t, err)

	_, err = srv.ReleaseLease(context.Background(), &databroker.ReleaseLeaseRequest{
		Name: "TEST",
		Id:   res.GetId(),
	})
	assert.NoError(t, err)
}

func TestServer_Query(t *testing.T) {
	cfg := newServerConfig()
	srv := newServer(cfg)

	for i := 0; i < 10; i++ {
		s := new(session.Session)
		s.Id = fmt.Sprint(i)
		data := protoutil.NewAny(s)
		_, err := srv.Put(context.Background(), &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)
	}
	res, err := srv.Query(context.Background(), &databroker.QueryRequest{
		Type: protoutil.GetTypeURL(new(session.Session)),
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
	cfg := newServerConfig()
	srv := newServer(cfg)

	s := new(session.Session)
	s.Id = "1"
	data := protoutil.NewAny(s)
	_, err := srv.Put(context.Background(), &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	assert.NoError(t, err)

	gs := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(gs, srv)
	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer li.Close()

	eg, ctx := errgroup.WithContext(context.Background())
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

		client := databroker.NewDataBrokerServiceClient(cc)
		syncer := databroker.NewSyncer("TEST", testSyncerHandler{
			getDataBrokerServiceClient: func() databroker.DataBrokerServiceClient {
				return client
			},
			clearRecords: func(_ context.Context) {
				clearRecords <- struct{}{}
			},
			updateRecords: func(_ context.Context, recordVersion uint64, _ []*databroker.Record) {
				updateRecords <- recordVersion
			},
		})
		go syncer.Run(ctx)
		select {
		case <-clearRecords:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-updateRecords:
		case <-ctx.Done():
			return ctx.Err()

		}

		_, err = srv.Put(context.Background(), &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)

		select {
		case <-updateRecords:
		case <-ctx.Done():
			return ctx.Err()

		}
		return nil
	})
	assert.NoError(t, eg.Wait())
}

func TestServerInvalidStorage(t *testing.T) {
	srv := newServer(&serverConfig{
		storageType: "<INVALID>",
	})

	s := new(session.Session)
	s.Id = "1"
	data := protoutil.NewAny(s)
	_, err := srv.Put(context.Background(), &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.TypeUrl,
			Id:   s.Id,
			Data: data,
		}},
	})
	_ = assert.Error(t, err) && assert.Contains(t, err.Error(), "unsupported storage type")
}

func TestServerPostgres(t *testing.T) {
	t.Parallel()

	testutil.WithTestPostgres(t, func(dsn string) {
		srv := newServer(&serverConfig{
			storageType:             "postgres",
			storageConnectionString: dsn,
		})

		s := new(session.Session)
		s.Id = "1"
		data := protoutil.NewAny(s)
		_, err := srv.Put(context.Background(), &databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: data.TypeUrl,
				Id:   s.Id,
				Data: data,
			}},
		})
		assert.NoError(t, err)

		gs := grpc.NewServer()
		databroker.RegisterDataBrokerServiceServer(gs, srv)
		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer li.Close()

		eg, ctx := errgroup.WithContext(context.Background())
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

			client := databroker.NewDataBrokerServiceClient(cc)
			stream, err := client.SyncLatest(ctx, &databroker.SyncLatestRequest{
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
