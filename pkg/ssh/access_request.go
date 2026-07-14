package ssh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/common"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type inflightAccessRequest struct {
	request *session.StreamAccessRequest
	updateC chan *databroker.Record

	replyOnce sync.Once
}

type StreamAccessRequestManager struct {
	client databroker.ClientGetter
	done   chan struct{}

	inflightAccessRequestsMu sync.Mutex
	inflightAccessRequests   map[string]*inflightAccessRequest
}

var streamAccessRequestTypeUrl = protoutil.GetTypeURL(&session.StreamAccessRequest{})

func NewStreamAccessRequestManager(ctx context.Context, client databroker.ClientGetter) *StreamAccessRequestManager {
	m := &StreamAccessRequestManager{
		client:                 client,
		inflightAccessRequests: map[string]*inflightAccessRequest{},
		done:                   make(chan struct{}),
	}

	eg, ctxca := errgroup.WithContext(ctx)

	eg.Go(func() error {
		syncer := databrokerutil.NewSyncer(
			ctxca,
			"access-request-syncer",
			m,
			databrokerutil.WithTypeURL(streamAccessRequestTypeUrl),
		)
		return syncer.Run(ctxca)
	})
	go func() {
		defer close(m.done)
		_ = eg.Wait()
	}()
	return m
}

func (m *StreamAccessRequestManager) Done() chan struct{} {
	return m.done
}

func (m *StreamAccessRequestManager) DoRequest(streamCtx context.Context, req *session.StreamAccessRequest) error {
	streamID := req.StreamId
	recordID := fmt.Sprintf("%x", streamID)

	req.Approved = false

	lg := log.Ctx(streamCtx).With().
		Str("protocol", req.Protocol).
		Str("sessionId", req.SessionId).
		Str("streamId", recordID).
		Str("userId", req.UserId).
		Logger()

	streamCtxWithDeadline, ca := context.WithDeadline(streamCtx, req.ExpiresAt.AsTime())
	defer ca()

	m.inflightAccessRequestsMu.Lock()

	if _, ok := m.inflightAccessRequests[recordID]; ok {
		// this should never happen
		m.inflightAccessRequestsMu.Unlock()
		return status.Errorf(codes.Internal, "duplicate access request for stream %d", streamID)
	}

	if _, err := m.client.GetDataBrokerServiceClient().Put(streamCtxWithDeadline, &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type: grpcutil.GetTypeURL(req),
				Id:   recordID,
				Data: protoutil.NewAny(req),
			},
		},
	}); err != nil {
		m.inflightAccessRequestsMu.Unlock()
		lg.Err(err).Msg("error creating StreamAccessRequest broker record")
		return status.Errorf(codes.Internal, "error creating access request")
	}

	inflightReq := &inflightAccessRequest{
		request: req,
		updateC: make(chan *databroker.Record, 1),
	}
	m.inflightAccessRequests[recordID] = inflightReq

	m.inflightAccessRequestsMu.Unlock()

	var recordDeleted bool
	defer func() {
		m.inflightAccessRequestsMu.Lock()
		delete(m.inflightAccessRequests, recordID)
		m.inflightAccessRequestsMu.Unlock()

		if recordDeleted {
			return
		}
		_, err := storage.DeleteDataBrokerRecord(
			context.Background(),
			m.GetDataBrokerServiceClient(),
			streamAccessRequestTypeUrl,
			recordID)
		if err != nil {
			lg.Err(err).Msg("error deleting databroker record")
		}
	}()

	for {
		select {
		case <-m.done:
			return status.Error(codes.Canceled, "canceled")
		case <-streamCtxWithDeadline.Done():
			return status.FromContextError(context.Cause(streamCtxWithDeadline)).Err()
		case record := <-inflightReq.updateC:
			if record.DeletedAt != nil {
				recordDeleted = true
				return status.Errorf(codes.PermissionDenied, "access request denied")
			}
			var req session.StreamAccessRequest
			if err := record.GetData().UnmarshalTo(&req); err != nil {
				lg.Err(err).Str("id", record.GetId()).Msg("StreamAccessRequest record has missing or invalid data")
				return status.Errorf(codes.Internal, "error processing access request")
			}
			if req.Approved {
				// Check if the request is expired or if it was modified after the expiration time
				if exp := req.ExpiresAt.AsTime(); exp.Before(time.Now()) || record.ModifiedAt.AsTime().After(exp) {
					lg.Warn().Msg("StreamAccessRequest approved after expiry, denying")
					return status.Errorf(codes.DeadlineExceeded, "timed out waiting for access request approval")
				} else {
					lg.Warn().Str("id", recordID).Msg("StreamAccessRequest approved")
					return nil // approved
				}
			}
		}
	}
}

// ClearRecords implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) ClearRecords(ctx context.Context) {
	m.inflightAccessRequestsMu.Lock()
	defer m.inflightAccessRequestsMu.Unlock()

	now := timestamppb.Now()
	for id, req := range m.inflightAccessRequests {
		req.updateC <- &databroker.Record{
			Type:      streamAccessRequestTypeUrl,
			Id:        id,
			DeletedAt: now,
		}
	}
}

// GetDataBrokerServiceClient implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return m.client.GetDataBrokerServiceClient()
}

// UpdateRecords implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	m.inflightAccessRequestsMu.Lock()
	defer m.inflightAccessRequestsMu.Unlock()

	for _, record := range records {
		if pending, ok := m.inflightAccessRequests[record.Id]; ok {
			pending.updateC <- record
		}
	}
}

func (m *StreamAccessRequestManager) verifyPendingRequest(ctx context.Context, client databroker.DataBrokerServiceClient, requestID string, arbitrator *session.Session) error {
	record, err := client.Get(ctx, &databroker.GetRequest{
		Type: streamAccessRequestTypeUrl,
		Id:   requestID,
	})
	if err != nil {
		if databroker.IsNotFound(err) {
			return status.Errorf(codes.NotFound, "request not found")
		}
		return err
	}

	if record.GetRecord().GetDeletedAt() != nil {
		// already denied/canceled
		return status.Errorf(codes.NotFound, "request was already denied or canceled")
	}
	var req session.StreamAccessRequest
	if err := record.GetRecord().GetData().UnmarshalTo(&req); err != nil {
		return status.Errorf(codes.Internal, "request is not valid")
	}
	if req.UserId == arbitrator.UserId || req.SessionId == arbitrator.Id {
		return status.Errorf(codes.PermissionDenied, "you may not approve or deny your own requests")
	}
	if req.Approved {
		// already approved
		return status.Errorf(codes.NotFound, "request was already approved")
	}
	if req.ExpiresAt.AsTime().Before(time.Now()) {
		return status.Errorf(codes.InvalidArgument, "request is expired")
	}
	return nil
}

// ApproveRequest implements [api.AccessRequestManagerInterface].
func (m *StreamAccessRequestManager) ApproveRequest(ctx context.Context, requestID string, arbitrator *session.Session) error {
	client := m.client.GetDataBrokerServiceClient()

	err := m.verifyPendingRequest(ctx, client, requestID, arbitrator)
	if err != nil {
		return err
	}

	_, err = client.Patch(ctx, &databroker.PatchRequest{
		FieldMask: &fieldmaskpb.FieldMask{
			Paths: []string{"approved"},
		},
		Records: []*databroker.Record{
			{
				Type: streamAccessRequestTypeUrl,
				Id:   requestID,
				Data: protoutil.NewAny(&session.StreamAccessRequest{
					Approved: true,
				}),
			},
		},
	})
	return err
}

// DenyRequest implements [api.AccessRequestManagerInterface].
func (m *StreamAccessRequestManager) DenyRequest(ctx context.Context, requestID string, arbitrator *session.Session) error {
	client := m.client.GetDataBrokerServiceClient()

	err := m.verifyPendingRequest(ctx, client, requestID, arbitrator)
	if err != nil {
		return err
	}

	_, err = storage.DeleteDataBrokerRecord(ctx, client, streamAccessRequestTypeUrl, requestID)
	return err
}

// ListPendingRequests implements [api.AccessRequestManagerInterface].
func (m *StreamAccessRequestManager) ListPendingRequests(filter []common.RouteInfo) []*session.StreamAccessRequest {
	if len(filter) == 0 {
		return []*session.StreamAccessRequest{}
	}

	authorizedClusterIds := make(map[string]struct{}, len(filter))
	for _, info := range filter {
		authorizedClusterIds[info.ClusterID] = struct{}{}
	}

	m.inflightAccessRequestsMu.Lock()
	defer m.inflightAccessRequestsMu.Unlock()

	if len(m.inflightAccessRequests) == 0 {
		return []*session.StreamAccessRequest{}
	}

	filteredRequests := make([]*session.StreamAccessRequest, 0, min(len(filter), len(m.inflightAccessRequests)))
	for _, v := range m.inflightAccessRequests {
		if _, ok := authorizedClusterIds[v.request.ClusterId]; ok {
			filteredRequests = append(filteredRequests, v.request)
		}
	}

	return filteredRequests
}
