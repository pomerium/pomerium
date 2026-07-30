package ssh_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/storage"
)

type wrapperGetter struct {
	client databrokerpb.DataBrokerServiceClient
}

var _ databrokerpb.ClientGetter = wrapperGetter{}

func (g wrapperGetter) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return g.client
}

func initDatabrokerServer(t *testing.T, server ...databrokerpb.DataBrokerServiceServer) (databrokerpb.DataBrokerServiceClient, databrokerpb.ClientGetter) {
	t.Helper()
	var srv databrokerpb.DataBrokerServiceServer
	if len(server) == 0 {
		srv = databroker.NewBackendServer(noop.NewTracerProvider())
	} else {
		srv = server[0]
	}
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		s.RegisterService(&databrokerpb.DataBrokerService_ServiceDesc, srv)
	})
	client := databrokerpb.NewDataBrokerServiceClient(cc)
	return client, wrapperGetter{client: client}
}

func waitForRequestCreated(t *testing.T, client databrokerpb.DataBrokerServiceClient, streamID uint64) {
	ctx, ca := context.WithTimeout(t.Context(), 10*time.Second)
	defer ca()
	err := retry.Retry(ctx, "waitForRequestCreated", func(ctx context.Context) error {
		_, err := client.Get(ctx, &databrokerpb.GetRequest{
			Type: "type.googleapis.com/session.StreamAccessRequest",
			Id:   fmt.Sprintf("%x", streamID),
		})
		if err != nil {
			if databrokerpb.IsNotFound(err) {
				return err
			}
			return retry.NewTerminalError(err)
		}
		return nil
	}, retry.WithInitialInterval(1*time.Millisecond), retry.WithMaxInterval(100*time.Millisecond))
	require.NoError(t, err, "timed out waiting for StreamAccessRequest to be created")
}

func waitForRequestDeleted(t *testing.T, client databrokerpb.DataBrokerServiceClient, streamID uint64) {
	ctx, ca := context.WithTimeout(t.Context(), 10*time.Second)
	defer ca()
	err := retry.Retry(ctx, "waitForRequestDeleted", func(ctx context.Context) error {
		record, err := client.Get(ctx, &databrokerpb.GetRequest{
			Type: "type.googleapis.com/session.StreamAccessRequest",
			Id:   fmt.Sprintf("%x", streamID),
		})
		if err != nil {
			if databrokerpb.IsNotFound(err) {
				return nil
			}
			return retry.NewTerminalError(err)
		}
		if record.GetRecord().DeletedAt == nil {
			return errors.New("record is not deleted yet")
		}
		return nil
	}, retry.WithInitialInterval(1*time.Millisecond), retry.WithMaxInterval(100*time.Millisecond))
	require.NoError(t, err, "timed out waiting for StreamAccessRequest to be deleted")
}

func approveRequest(t *testing.T, client databrokerpb.DataBrokerServiceClient, streamID uint64) {
	_, err := client.Patch(t.Context(), &databrokerpb.PatchRequest{
		FieldMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state"},
		},
		Records: []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", streamID),
				Data: marshalAny(&session.StreamAccessRequest{
					State: session.StreamAccessRequest_Approved,
				}),
			},
		},
	})
	require.NoError(t, err)
}

func denyRequest(t *testing.T, client databrokerpb.DataBrokerServiceClient, streamID uint64) {
	_, err := client.Patch(t.Context(), &databrokerpb.PatchRequest{
		FieldMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state"},
		},
		Records: []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", streamID),
				Data: marshalAny(&session.StreamAccessRequest{
					State: session.StreamAccessRequest_Denied,
				}),
			},
		},
	})
	require.NoError(t, err)
}

func newRequestParams(streamID uint64) *session.StreamAccessRequestParams {
	return &session.StreamAccessRequestParams{
		Protocol:  "ssh",
		SessionId: fmt.Sprintf("fake-session-id-%d", streamID),
		UserId:    fmt.Sprintf("fake-user-id-%d", streamID),
		StreamId:  streamID,
		ClusterId: fmt.Sprintf("fake-cluster-id-%d", streamID),
	}
}

func TestRequestManager(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()
	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	t.Run("approve request", func(t *testing.T) {
		replyC := make(chan ssh.AccessRequestReply, 1)
		go func() {
			defer close(replyC)
			streamCtx, streamCa := context.WithCancel(t.Context())
			defer streamCa()
			reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
			assert.NoError(t, err)
			replyC <- reply
		}()

		waitForRequestCreated(t, client, 1)

		approveRequest(t, client, 1)

		select {
		case reply := <-replyC:
			assert.True(t, reply.Approved)
			waitForRequestDeleted(t, client, 1)
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for reply")
		}
	})

	t.Run("deny request", func(t *testing.T) {
		replyC := make(chan ssh.AccessRequestReply, 1)
		go func() {
			defer close(replyC)
			streamCtx, streamCa := context.WithCancel(t.Context())
			defer streamCa()
			reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(2))
			assert.NoError(t, err)
			replyC <- reply
		}()

		waitForRequestCreated(t, client, 2)

		denyRequest(t, client, 2)

		select {
		case reply := <-replyC:
			assert.False(t, reply.Approved)
			waitForRequestDeleted(t, client, 2)
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for reply")
		}
	})
}

func TestRequestManager_MultiInstance(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)
	n := 5

	replies := make([]chan ssh.AccessRequestReply, n)
	for i := range n {
		replies[i] = make(chan ssh.AccessRequestReply, 1)
	}

	for i := range n {
		go func() {
			ctx, ca := context.WithCancel(t.Context())
			defer ca()
			mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

			streamCtx, streamCa := context.WithCancel(t.Context())
			defer streamCa()

			defer close(replies[i])
			reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(uint64(i)))
			assert.NoError(t, err)
			replies[i] <- reply
		}()
	}

	for i := range n {
		waitForRequestCreated(t, client, uint64(i))
	}

	for i := range n {
		if i%2 == 0 {
			approveRequest(t, client, uint64(i))
		} else {
			denyRequest(t, client, uint64(i))
		}
	}

	for i := range n {
		select {
		case reply := <-replies[i]:
			if i%2 == 0 {
				assert.True(t, reply.Approved)
			} else {
				assert.False(t, reply.Approved)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for reply")
		}
	}

	for i := range n {
		waitForRequestDeleted(t, client, uint64(i))
	}
}

func TestRequestManager_ConcurrentApprovalOrDenial(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)
	ctx, ca := context.WithCancel(t.Context())
	defer ca()
	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	n := 100 // must be even

	replies := make([]chan ssh.AccessRequestReply, n)
	for i := range n {
		replies[i] = make(chan ssh.AccessRequestReply, 1)
	}

	for i := range n {
		go func() {
			defer close(replies[i])
			streamCtx, streamCa := context.WithCancel(ctx)
			defer streamCa()
			reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(uint64(i)))
			assert.NoError(t, err)
			replies[i] <- reply
		}()
	}

	for i := range n {
		waitForRequestCreated(t, client, uint64(i))
	}

	for i := range n {
		a, b := session.StreamAccessRequest_Approved, session.StreamAccessRequest_Denied
		if i%2 == 0 {
			a, b = b, a
		}
		patches := []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", i),
				Data: marshalAny(&session.StreamAccessRequest{
					State: a,
				}),
			},
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", i),
				Data: marshalAny(&session.StreamAccessRequest{
					State: b,
				}),
			},
		}
		_, err := client.Patch(t.Context(), &databrokerpb.PatchRequest{
			FieldMask: &fieldmaskpb.FieldMask{
				Paths: []string{"state"},
			},
			Records: patches,
		})
		assert.NoError(t, err)
	}

	var numApprovals, numDenials int
	for i := range n {
		select {
		case reply := <-replies[i]:
			if reply.Approved {
				numApprovals++
			} else {
				numDenials++
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for reply")
		}
	}

	for i := range n {
		waitForRequestDeleted(t, client, uint64(i))
	}

	assert.Equal(t, numApprovals, n/2)
	assert.Equal(t, numDenials, n/2)
}

func TestRequestManager_ShutdownCancel(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	errC := make(chan error, 1)
	go func() {
		defer close(errC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		_, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		errC <- err
	}()

	waitForRequestCreated(t, client, 1)
	time.Sleep(100 * time.Millisecond) // give the syncer time to receive the new request
	ca()

	select {
	case err := <-errC:
		assert.ErrorContains(t, err, "server shutting down")
		waitForRequestDeleted(t, client, 1)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestManager_RecordExpires(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	errC := make(chan error, 1)
	go func() {
		defer close(errC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		_, err := mgr.DoRequest(streamCtx, 200*time.Millisecond, newRequestParams(1))
		require.Error(t, err)
		errC <- err
	}()

	waitForRequestCreated(t, client, 1)

	select {
	case err := <-errC:
		assert.ErrorContains(t, err, "access request expired")
		waitForRequestDeleted(t, client, 1)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for request to expire")
	}
}

func TestRequestManager_StaleRecords(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	_, err := client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", 1234),
				Data: marshalAny(&session.StreamAccessRequest{
					Params:    newRequestParams(1234),
					CreatedAt: timestamppb.New(time.Now().Add(-2 * time.Minute)),
					ExpiresAt: timestamppb.New(time.Now().Add(-1 * time.Minute)),
					State:     session.StreamAccessRequest_Pending,
				}),
			},
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", 2345),
				Data: marshalAny(&session.StreamAccessRequest{
					Params:    newRequestParams(2345),
					CreatedAt: timestamppb.New(time.Now().Add(-2 * time.Minute)),
					ExpiresAt: timestamppb.New(time.Now().Add(-1 * time.Minute)),
					State:     session.StreamAccessRequest_Approved,
				}),
			},
		},
	})
	require.NoError(t, err)

	waitForRequestCreated(t, client, 1234)
	waitForRequestCreated(t, client, 2345)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)
	waitForRequestDeleted(t, client, 1234)
	waitForRequestDeleted(t, client, 2345)
	_ = mgr
}

func TestRequestManager_RequestRecordsDeleted(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	replyC := make(chan ssh.AccessRequestReply, 1)
	go func() {
		defer close(replyC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		assert.NoError(t, err)
		replyC <- reply
	}()

	waitForRequestCreated(t, client, 1)

	_, err := storage.DeleteDataBrokerRecord(
		t.Context(),
		client,
		"type.googleapis.com/session.StreamAccessRequest",
		"1")
	require.NoError(t, err)

	select {
	case reply := <-replyC:
		assert.False(t, reply.Approved)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestManager_StreamCanceled(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	streamCtx, streamCa := context.WithCancel(t.Context())

	errC := make(chan error, 1)
	go func() {
		defer close(errC)
		_, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		errC <- err
	}()

	waitForRequestCreated(t, client, 1)

	streamCa()

	select {
	case err := <-errC:
		assert.ErrorIs(t, err, status.Error(codes.Canceled, "context canceled"))
		waitForRequestDeleted(t, client, 1)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestManager_DatabrokerClear(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	replyC1 := make(chan ssh.AccessRequestReply, 1)
	go func() {
		defer close(replyC1)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		assert.NoError(t, err)
		replyC1 <- reply
	}()

	replyC2 := make(chan ssh.AccessRequestReply, 1)
	go func() {
		defer close(replyC2)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(2))
		assert.NoError(t, err)
		replyC2 <- reply
	}()

	waitForRequestCreated(t, client, 1)
	waitForRequestCreated(t, client, 2)

	_, err := client.Clear(ctx, &emptypb.Empty{})
	require.NoError(t, err)

	select {
	case reply := <-replyC1:
		assert.False(t, reply.Approved)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}

	select {
	case reply := <-replyC2:
		assert.False(t, reply.Approved)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestManager_IgnoreInvalidRecords(t *testing.T) {
	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	_, err := client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", 1),
				Data: nil,
			},
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", 2),
				Data: marshalAny(&session.StreamAccessRequest{
					Params:    newRequestParams(2),
					CreatedAt: timestamppb.New(time.Now()),
					ExpiresAt: timestamppb.New(time.Now().Add(1 * time.Minute)),
					State:     session.StreamAccessRequest_Approved,
				}),
			},
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", 3),
				Data: marshalAny(&session.StreamAccessRequest{
					Params:    newRequestParams(3),
					CreatedAt: timestamppb.New(time.Now()),
					ExpiresAt: timestamppb.New(time.Now().Add(1 * time.Minute)),
					State:     session.StreamAccessRequest_Denied,
				}),
			},
		},
	})
	require.NoError(t, err)

	waitForRequestCreated(t, client, 1)
	waitForRequestCreated(t, client, 2)
	waitForRequestCreated(t, client, 3)

	replyC := make(chan ssh.AccessRequestReply, 1)
	go func() {
		defer close(replyC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(4))
		assert.NoError(t, err)
		replyC <- reply
	}()

	waitForRequestCreated(t, client, 4)

	approveRequest(t, client, 4)

	select {
	case reply := <-replyC:
		assert.True(t, reply.Approved)
		waitForRequestDeleted(t, client, 4)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

type srvDatabrokerPutError struct {
	databrokerpb.DataBrokerServiceServer
}

func (m *srvDatabrokerPutError) SyncLatest(_ *databrokerpb.SyncLatestRequest, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	stream.Send(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Versions{Versions: &databrokerpb.Versions{}},
	})
	return nil
}

func (m *srvDatabrokerPutError) Sync(_ *databrokerpb.SyncRequest, stream databrokerpb.DataBrokerService_SyncServer) error {
	<-stream.Context().Done()
	return nil
}

func (m *srvDatabrokerPutError) Put(context.Context, *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	return nil, status.Errorf(codes.Internal, "test error")
}

var _ databrokerpb.DataBrokerServiceServer = (*srvDatabrokerPutError)(nil)

func TestRequestManager_DatabrokerPutError(t *testing.T) {
	t.Parallel()

	_, clientGetter := initDatabrokerServer(t, &srvDatabrokerPutError{})
	mgr := ssh.NewStreamAccessRequestManager(t.Context(), clientGetter)

	errC := make(chan error, 1)
	go func() {
		defer close(errC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		_, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		errC <- err
	}()

	select {
	case err := <-errC:
		assert.ErrorContains(t, err, "error creating access request")
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

type srvDatabrokerInitialSyncError struct {
	databrokerpb.DataBrokerServiceServer
}

func (m *srvDatabrokerInitialSyncError) SyncLatest(_ *databrokerpb.SyncLatestRequest, _ databrokerpb.DataBrokerService_SyncLatestServer) error {
	return status.Errorf(codes.Internal, "test error")
}

var _ databrokerpb.DataBrokerServiceServer = (*srvDatabrokerInitialSyncError)(nil)

func TestRequestManager_DatabrokerInitialSyncError(t *testing.T) {
	t.Parallel()
	_, clientGetter := initDatabrokerServer(t, &srvDatabrokerInitialSyncError{})
	mgr := ssh.NewStreamAccessRequestManager(t.Context(), clientGetter)
	_, err := mgr.DoRequest(t.Context(), 100*time.Millisecond, newRequestParams(1))
	assert.ErrorIs(t, err, status.Errorf(codes.Unavailable, "timed out waiting for databroker sync"))
}

type srvDatabrokerDeleteError struct {
	databrokerpb.DataBrokerServiceServer
}

func (m *srvDatabrokerDeleteError) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	if req.Records[0].DeletedAt != nil {
		return nil, status.Errorf(codes.Internal, "test error")
	}
	return m.DataBrokerServiceServer.Put(ctx, req)
}

var _ databrokerpb.DataBrokerServiceServer = (*srvDatabrokerDeleteError)(nil)

func TestRequestManager_DatabrokerDeleteError(t *testing.T) {
	t.Parallel()
	client, clientGetter := initDatabrokerServer(t, &srvDatabrokerDeleteError{
		DataBrokerServiceServer: databroker.NewBackendServer(noop.NewTracerProvider()),
	})
	mgr := ssh.NewStreamAccessRequestManager(t.Context(), clientGetter)
	replyC := make(chan ssh.AccessRequestReply, 1)
	go func() {
		defer close(replyC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		assert.NoError(t, err)
		replyC <- reply
	}()

	waitForRequestCreated(t, client, 1)

	approveRequest(t, client, 1)

	select {
	case reply := <-replyC:
		assert.True(t, reply.Approved)
		time.Sleep(100 * time.Millisecond)
		waitForRequestCreated(t, client, 1) // the request should not be deleted
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

type srvShutdownBeforeNewRecordSynced struct {
	onRecordCreated func()
	databrokerpb.DataBrokerServiceServer
}

func (m *srvShutdownBeforeNewRecordSynced) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	m.onRecordCreated()
	return m.DataBrokerServiceServer.Put(ctx, req)
}

var _ databrokerpb.DataBrokerServiceServer = (*srvShutdownBeforeNewRecordSynced)(nil)

func TestRequestManager_ShutdownBeforeNewRecordSynced(t *testing.T) {
	t.Parallel()

	ctx, ca := context.WithCancel(t.Context())

	_, clientGetter := initDatabrokerServer(t, &srvShutdownBeforeNewRecordSynced{
		DataBrokerServiceServer: databroker.NewBackendServer(noop.NewTracerProvider()),
		onRecordCreated:         ca,
	})
	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	errC := make(chan error, 1)
	go func() {
		defer close(errC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		_, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		errC <- err
	}()

	select {
	case err := <-errC:
		assert.ErrorContains(t, err, "server shutting down")
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

type srvStreamShutdownBeforeNewRecordSynced struct {
	onRecordDropped func()
	databrokerpb.DataBrokerServiceServer
}

type streamWrapper struct {
	grpc.ServerStreamingServer[databrokerpb.SyncResponse]
	onRecordDropped func()
}

func (sw *streamWrapper) Send(resp *databrokerpb.SyncResponse) error {
	if resp.GetRecord().GetType() == "type.googleapis.com/session.StreamAccessRequest" &&
		resp.GetRecord().GetId() == "1" {
		sw.onRecordDropped()
		return nil
	}
	return sw.ServerStreamingServer.Send(resp)
}

func (m *srvStreamShutdownBeforeNewRecordSynced) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return m.DataBrokerServiceServer.Sync(req, &streamWrapper{
		ServerStreamingServer: stream,
		onRecordDropped:       m.onRecordDropped,
	})
}

var _ databrokerpb.DataBrokerServiceServer = (*srvStreamShutdownBeforeNewRecordSynced)(nil)

func TestRequestManager_StreamShutdownBeforeNewRecordSynced(t *testing.T) {
	t.Parallel()

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	streamCtx, streamCa := context.WithCancel(t.Context())

	_, clientGetter := initDatabrokerServer(t, &srvStreamShutdownBeforeNewRecordSynced{
		DataBrokerServiceServer: databroker.NewBackendServer(noop.NewTracerProvider()),
		onRecordDropped: func() {
			go func() {
				time.Sleep(100 * time.Millisecond) // allow the Put request to succeed
				streamCa()
			}()
		},
	})
	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	errC := make(chan error, 1)
	go func() {
		defer close(errC)
		_, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		errC <- err
	}()

	select {
	case err := <-errC:
		assert.ErrorIs(t, err, status.Error(codes.Canceled, "context canceled"))
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestManager_RequestApprovedAfterExpiry(t *testing.T) {
	// This situation is not likely to happen in practice except by approving
	// the request exactly as it expires, then getting unlucky timing. In that
	// case it is not an issue if the request is accepted; the check mainly
	// exists to guard against possible future bugs. It can be tested easily by
	// modifying the ExpiresAt field of the request to be earlier than the actual
	// expiration.

	t.Parallel()

	client, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()
	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	replyC := make(chan ssh.AccessRequestReply, 1)
	go func() {
		defer close(replyC)
		streamCtx, streamCa := context.WithCancel(t.Context())
		defer streamCa()
		reply, err := mgr.DoRequest(streamCtx, 10*time.Second, newRequestParams(1))
		assert.NoError(t, err)
		replyC <- reply
	}()

	waitForRequestCreated(t, client, 1)

	_, err := client.Patch(t.Context(), &databrokerpb.PatchRequest{
		FieldMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state", "expires_at"},
		},
		Records: []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.StreamAccessRequest",
				Id:   fmt.Sprintf("%x", uint64(1)),
				Data: marshalAny(&session.StreamAccessRequest{
					State:     session.StreamAccessRequest_Approved,
					ExpiresAt: timestamppb.New(time.Now().Add(-1 * time.Microsecond)),
				}),
			},
		},
	})
	require.NoError(t, err)

	select {
	case reply := <-replyC:
		assert.False(t, reply.Approved)
		waitForRequestDeleted(t, client, 1)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reply")
	}
}

func TestRequestManager_ShutDown(t *testing.T) {
	t.Parallel()
	srv := &srvDatabrokerInitialSyncError{}
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		s.RegisterService(&databrokerpb.DataBrokerService_ServiceDesc, srv)
	})

	ctx, ca := context.WithCancel(t.Context())
	mgr := ssh.NewStreamAccessRequestManager(ctx, wrapperGetter{client: databrokerpb.NewDataBrokerServiceClient(cc)})
	time.Sleep(100 * time.Millisecond)
	ca()

	_, err := mgr.DoRequest(t.Context(), 10*time.Second, newRequestParams(1))
	assert.ErrorIs(t, err, status.Errorf(codes.Unavailable, "server stopped"))
}

func TestRequestManager_DuplicateRecords(t *testing.T) {
	t.Parallel()

	_, clientGetter := initDatabrokerServer(t)

	ctx, ca := context.WithCancel(t.Context())
	defer ca()
	mgr := ssh.NewStreamAccessRequestManager(ctx, clientGetter)

	// There should never be duplicate requests for the same stream ID. Or at
	// least, it would be rather unlikely.
	go mgr.DoRequest(ctx, 10*time.Second, newRequestParams(1))
	_, err := mgr.DoRequest(ctx, 10*time.Second, newRequestParams(1))
	assert.ErrorContains(t, err, "duplicate access request for stream 1")
}
