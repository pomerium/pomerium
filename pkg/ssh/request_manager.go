package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AccessRequestReply struct {
	Approved bool
	Metadata map[string]string
}

type inflightAccessRequest struct {
	created chan struct{}
	reply   chan AccessRequestReply
	replied bool
}

func (r *inflightAccessRequest) Approve(metadata map[string]string) bool {
	if r.replied {
		return false
	}
	r.replied = true
	r.reply <- AccessRequestReply{Approved: true, Metadata: metadata}
	return true
}

func (r *inflightAccessRequest) Deny(metadata map[string]string) bool {
	if r.replied {
		return false
	}
	r.replied = true
	r.reply <- AccessRequestReply{Approved: false, Metadata: metadata}
	return true
}

type accessRequestCacheEntry struct {
	Request *session.StreamAccessRequest
	Local   bool // If true, the request is for a stream local to this instance
}

type accessRequestCache struct {
	mu       sync.Mutex
	requests map[string]accessRequestCacheEntry
}

func newAccessRequestCache() *accessRequestCache {
	return &accessRequestCache{
		requests: map[string]accessRequestCacheEntry{},
	}
}

func (c *accessRequestCache) Add(requestID string, request *session.StreamAccessRequest, local bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.requests[requestID]; ok {
		panic("bug: access request added twice")
	}
	c.requests[requestID] = accessRequestCacheEntry{
		Request: request,
		Local:   local,
	}
}

func (c *accessRequestCache) Update(requestID string, request *session.StreamAccessRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.requests[requestID]; !ok {
		panic("bug: access request does not exist")
	} else {
		c.requests[requestID] = accessRequestCacheEntry{
			Request: request,
			Local:   r.Local,
		}
	}
}

func (c *accessRequestCache) Delete(requestID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.requests, requestID)
}

func (c *accessRequestCache) Get(requestID string) (accessRequestCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.requests[requestID]
	return e, ok
}

func (c *accessRequestCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.requests)
}

type StreamAccessRequestManager struct {
	client databroker.ClientGetter
	done   chan struct{}

	requestCache *accessRequestCache

	localWaitingStreamsMu sync.Mutex
	localWaitingStreams   map[string]*inflightAccessRequest

	startTime          time.Time
	initialSyncDone    bool
	waitForInitialSync chan struct{}
}

var streamAccessRequestTypeUrl = protoutil.GetTypeURL(&session.StreamAccessRequest{})

func NewStreamAccessRequestManager(ctx context.Context, client databroker.ClientGetter) *StreamAccessRequestManager {
	m := &StreamAccessRequestManager{
		client:              client,
		localWaitingStreams: map[string]*inflightAccessRequest{},
		done:                make(chan struct{}),
		startTime:           time.Now(),
		requestCache:        newAccessRequestCache(),
		waitForInitialSync:  make(chan struct{}),
	}

	eg, ctxca := errgroup.WithContext(ctx)

	eg.Go(func() error {
		syncer := databrokerutil.NewSyncer(
			ctxca,
			"ssh-stream-access-request-syncer",
			m,
			databrokerutil.WithTypeURL(streamAccessRequestTypeUrl),
		)
		return syncer.Run(ctxca)
	})
	go func() {
		defer close(m.done)
		err := eg.Wait()
		log.Ctx(ctx).Debug().Err(err).Msg("stream access request syncer exited")
	}()
	return m
}

func (m *StreamAccessRequestManager) DoRequest(streamCtx context.Context, timeout time.Duration, params *session.StreamAccessRequestParams) (AccessRequestReply, error) {
	streamID := params.StreamId
	recordID := fmt.Sprintf("%x", streamID)

	now := time.Now()
	deadline := now.Add(timeout)
	streamCtxWithDeadline, ca := context.WithDeadline(streamCtx, deadline)
	defer ca()

	select {
	case <-m.waitForInitialSync:
	case <-m.done:
		return AccessRequestReply{}, status.Errorf(codes.Unavailable, "server stopped")
	case <-streamCtxWithDeadline.Done():
		return AccessRequestReply{}, status.Errorf(codes.Unavailable, "timed out waiting for databroker sync")
	}

	lg := log.Ctx(streamCtx).With().
		Str("protocol", params.Protocol).
		Str("session-id", params.SessionId).
		Str("user-id", params.UserId).
		Uint64("stream-id", params.StreamId).
		Str("cluster-id", params.ClusterId).
		Str("timeout", timeout.String()).
		Logger()

	m.localWaitingStreamsMu.Lock()

	if _, ok := m.localWaitingStreams[recordID]; ok {
		// this should never happen
		m.localWaitingStreamsMu.Unlock()
		return AccessRequestReply{}, status.Errorf(codes.Internal, "duplicate access request for stream %d", streamID)
	}

	createdC := make(chan struct{}, 1)
	replyC := make(chan AccessRequestReply, 1)

	m.localWaitingStreams[recordID] = &inflightAccessRequest{
		created: createdC,
		reply:   replyC,
	}

	m.localWaitingStreamsMu.Unlock()

	if _, err := m.client.GetDataBrokerServiceClient().Put(streamCtxWithDeadline, &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type: streamAccessRequestTypeUrl,
				Id:   recordID,
				Data: protoutil.NewAny(&session.StreamAccessRequest{
					Params:    params,
					CreatedAt: timestamppb.New(now),
					ExpiresAt: timestamppb.New(deadline),
				}),
			},
		},
	}); err != nil {
		// Handle cleanup separately here, since the order of operations in the
		// defer below is important. The stream should be removed from
		// m.localWaitingStreams before the record is deleted, to avoid confusing
		// log messages
		m.localWaitingStreamsMu.Lock()
		delete(m.localWaitingStreams, recordID)
		m.localWaitingStreamsMu.Unlock()

		lg.Err(err).Msg("error creating StreamAccessRequest record")
		return AccessRequestReply{}, status.Errorf(codes.Internal, "error creating access request")
	}

	defer func() {
		m.localWaitingStreamsMu.Lock()
		delete(m.localWaitingStreams, recordID)
		m.localWaitingStreamsMu.Unlock()

		_, err := storage.DeleteDataBrokerRecord(
			context.Background(),
			m.GetDataBrokerServiceClient(),
			streamAccessRequestTypeUrl,
			recordID)
		if err != nil {
			lg.Err(err).Msg("error deleting StreamAccessRequest databroker record; " +
				"this record may still exist and will not be deleted automatically until it expires")
		}
	}()

	select {
	case <-createdC:
		lg.Info().Msg("ssh: stream access request created")
	case <-m.done:
		lg.Info().Msg("ssh: stream access request canceled due to shutdown")
		return AccessRequestReply{}, status.Error(codes.Canceled, "server shutting down")
	case <-streamCtxWithDeadline.Done():
		err := status.FromContextError(context.Cause(streamCtxWithDeadline)).Err()
		lg.Err(err).Msg("ssh: timed out waiting for stream access request to be created")
		return AccessRequestReply{}, err
	}

	for {
		select {
		case <-m.done:
			lg.Info().Msg("ssh: stream access request canceled due to shutdown")
			return AccessRequestReply{}, status.Error(codes.Canceled, "server shutting down")
		case <-streamCtxWithDeadline.Done():
			cause := context.Cause(streamCtxWithDeadline)
			if errors.Is(cause, context.DeadlineExceeded) {
				lg.Info().Msg("ssh: stream access request denied (request expired)")
				return AccessRequestReply{}, status.Error(codes.DeadlineExceeded, "access request expired")
			}
			lg.Info().Err(cause).Msg("ssh: stream access request denied (canceled)")
			return AccessRequestReply{}, status.FromContextError(cause).Err()
		case reply := <-replyC:
			return reply, nil
		}
	}
}

// ClearRecords implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) ClearRecords(ctx context.Context) {
	if !m.initialSyncDone {
		m.initialSyncDone = true
		close(m.waitForInitialSync)
		return
	}

	m.localWaitingStreamsMu.Lock()
	for id, stream := range m.localWaitingStreams {
		log.Ctx(ctx).Info().Str("id", id).Msg("stream access request denied (databroker sync reset)")
		stream.Deny(nil)
	}
	m.localWaitingStreamsMu.Unlock()

	m.requestCache.Clear()
}

// GetDataBrokerServiceClient implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return m.client.GetDataBrokerServiceClient()
}

// UpdateRecords implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, record := range records {
		var req session.StreamAccessRequest
		if err := record.GetData().UnmarshalTo(&req); err != nil {
			log.Ctx(ctx).Error().Str("id", record.Id).Err(err).Msg("StreamAccessRequest record is invalid; ignoring")
			continue
		}
		lg := log.Ctx(ctx).With().
			Str("request-id", record.Id).
			Str("cluster-id", req.Params.ClusterId).
			Str("session-id", req.Params.SessionId).
			Str("user-id", req.Params.UserId).
			Logger()
		if record.DeletedAt != nil {
			if cached, ok := m.requestCache.Get(record.Id); ok {
				if cached.Local {
					m.localWaitingStreamsMu.Lock()
					if stream, ok := m.localWaitingStreams[record.Id]; ok {
						if stream.Deny(nil) {
							lg.Warn().Msg("stream access request denied: record deleted while the stream is still active")
						}
					}
					m.localWaitingStreamsMu.Unlock()
				}
				m.requestCache.Delete(record.Id)
			}
			continue
		} else if req.ExpiresAt.AsTime().Before(m.startTime) {
			// if the request expired before the server started but it is not deleted,
			// the record is stale and was probably left over from a previous instance
			// that was killed or if there was a databroker connection error, so try
			// to delete it
			lg.Debug().Str("expired-at", req.ExpiresAt.String()).
				Msg("deleting stale StreamAccessRequest databroker record")
			_, _ = storage.DeleteDataBrokerRecord(
				context.Background(),
				m.GetDataBrokerServiceClient(),
				streamAccessRequestTypeUrl,
				record.Id)
			continue
		}

		if cached, ok := m.requestCache.Get(record.Id); ok {
			// existing local record
			m.requestCache.Update(record.Id, &req)

			if cached.Local {
				m.localWaitingStreamsMu.Lock()

				if req.State != session.StreamAccessRequest_Pending {
					// the request is approved or denied. check if the stream for this request is
					// still waiting
					if stream, ok := m.localWaitingStreams[record.Id]; ok {
						if req.State == session.StreamAccessRequest_Approved {
							// Check if the request is expired or if it was modified after the expiration time
							if exp := req.ExpiresAt.AsTime(); exp.Before(time.Now()) || record.ModifiedAt.AsTime().After(exp) {
								if stream.Deny(req.Metadata) {
									lg.Warn().Any("metadata", req.Metadata).Msg("ssh: stream access request denied: approved after request expired")
								}
							} else {
								if stream.Approve(req.Metadata) {
									lg.Info().Any("metadata", req.Metadata).Msg("ssh: stream access request approved")
								}
							}
						} else {
							if stream.Deny(req.Metadata) {
								lg.Info().Any("metadata", req.Metadata).Msg("ssh: stream access request denied")
							}
						}
					}
				}

				m.localWaitingStreamsMu.Unlock()
			}
		} else {
			// new record
			if req.State == session.StreamAccessRequest_Pending {
				m.localWaitingStreamsMu.Lock()

				if stream, ok := m.localWaitingStreams[record.Id]; ok {
					// the record is for a local stream
					m.requestCache.Add(record.Id, &req, true)
					close(stream.created)
				} else {
					// the record is for a nonlocal stream
					m.requestCache.Add(record.Id, &req, false)
				}

				m.localWaitingStreamsMu.Unlock()
			} else {
				log.Ctx(ctx).Debug().Str("id", record.Id).Msg("ignoring new StreamAccessRequest record with non-pending state")
			}
		}
	}
}
