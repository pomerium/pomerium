package ssh

import (
	"context"
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

	startTime time.Time
}

var streamAccessRequestTypeUrl = protoutil.GetTypeURL(&session.StreamAccessRequest{})

func NewStreamAccessRequestManager(ctx context.Context, client databroker.ClientGetter) *StreamAccessRequestManager {
	m := &StreamAccessRequestManager{
		client:              client,
		localWaitingStreams: map[string]*inflightAccessRequest{},
		done:                make(chan struct{}),
		startTime:           time.Now(),
		requestCache:        newAccessRequestCache(),
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
		_ = eg.Wait()
	}()
	return m
}

func (m *StreamAccessRequestManager) Done() chan struct{} {
	return m.done
}

func (m *StreamAccessRequestManager) DoRequest(streamCtx context.Context, timeout time.Duration, params *session.StreamAccessRequestParams) (AccessRequestReply, error) {
	streamID := params.StreamId
	recordID := fmt.Sprintf("%x", streamID)

	lg := log.Ctx(streamCtx).With().
		Str("protocol", params.Protocol).
		Str("sessionId", params.SessionId).
		Str("streamId", recordID).
		Str("userId", params.UserId).
		Logger()

	now := time.Now()
	deadline := now.Add(timeout)
	streamCtxWithDeadline, ca := context.WithDeadline(streamCtx, deadline)
	defer ca()

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

	defer func() {
		m.localWaitingStreamsMu.Lock()
		delete(m.localWaitingStreams, recordID)
		m.localWaitingStreamsMu.Unlock()
	}()

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
		lg.Err(err).Msg("error creating StreamAccessRequest broker record")
		return AccessRequestReply{}, status.Errorf(codes.Internal, "error creating access request")
	}

	defer func() {
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
		lg.Debug().Msg("StreamAccessRequest was created successfully")
	case <-streamCtxWithDeadline.Done():
		err := status.FromContextError(context.Cause(streamCtxWithDeadline)).Err()
		lg.Err(err).Msg("timed out waiting for StreamAccessRequest to be created")
		return AccessRequestReply{}, err
	}

	for {
		select {
		case <-m.done:
			lg.Debug().Msg("StreamAccessRequest canceled due to shutdown")
			return AccessRequestReply{}, status.Error(codes.Canceled, "canceled")
		case <-streamCtxWithDeadline.Done():
			lg.Debug().Msg("StreamAccessRequest timed out or the associated stream was closed")
			return AccessRequestReply{}, status.FromContextError(context.Cause(streamCtxWithDeadline)).Err()
		case reply := <-replyC:
			return reply, nil
		}
	}
}

// ClearRecords implements [databrokerutil.SyncerHandler].
func (m *StreamAccessRequestManager) ClearRecords(ctx context.Context) {
	m.localWaitingStreamsMu.Lock()
	for _, req := range m.localWaitingStreams {
		req.Deny(nil)
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
		if record.DeletedAt != nil {
			if cached, ok := m.requestCache.Get(record.Id); ok {
				if cached.Local {
					m.localWaitingStreamsMu.Lock()
					if stream, ok := m.localWaitingStreams[record.Id]; ok {
						log.Ctx(ctx).Warn().Str("id", record.Id).Msg("StreamAccessRequest was deleted while the stream is still active; denying request")
						_ = stream.Deny(nil)
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
			log.Ctx(ctx).Info().Str("id", record.Id).Str("expired-at", req.ExpiresAt.String()).
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
						switch req.State {
						case session.StreamAccessRequest_Approved:
							// Check if the request is expired or if it was modified after the expiration time
							if exp := req.ExpiresAt.AsTime(); exp.Before(time.Now()) || record.ModifiedAt.AsTime().After(exp) {
								if stream.Deny(req.Metadata) {
									log.Ctx(ctx).Warn().Str("id", record.Id).Msg("Stream Access Request approved after expiry; denying request")
								}
							} else {
								if stream.Approve(req.Metadata) {
									log.Ctx(ctx).Info().Str("id", record.Id).Any("metadata", req.Metadata).Msg("Stream Access Request approved")
								}
							}
						case session.StreamAccessRequest_Denied:
							if stream.Deny(req.Metadata) {
								log.Ctx(ctx).Info().Str("id", record.Id).Any("metadata", req.Metadata).Msg("Stream Access Request denied")
							}
						default:
							panic("unreachable")
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
