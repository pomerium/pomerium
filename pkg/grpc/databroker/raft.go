package databroker

import (
	"context"
	"fmt"
	"io"
	"iter"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type RaftServer interface {
	ServeRaft(stream grpc.BidiStreamingServer[RaftRequest, RaftResponse]) error
	Stop()
	Transport(grpcutil.ClientManager) RaftTransport
}

type raftServer struct {
	localServerAddress raft.ServerAddress
	timeout            time.Duration

	cancelCtx context.Context
	cancel    context.CancelFunc

	consumerCh chan raft.RPC
}

type raftPendingResponsePayload struct {
	request *RaftRequest
	ch      chan raft.RPCResponse
}

// NewRaftServer creates a new RaftServer.
func NewRaftServer(
	localServerAddress raft.ServerAddress,
) RaftServer {
	srv := &raftServer{
		localServerAddress: localServerAddress,
		timeout:            10 * time.Second,

		consumerCh: make(chan raft.RPC, 1),
	}
	srv.cancelCtx, srv.cancel = context.WithCancel(context.Background())
	return srv
}

func (srv *raftServer) ServeRaft(stream grpc.BidiStreamingServer[RaftRequest, RaftResponse]) error {
	ctx, cancel := contextutil.Merge(stream.Context(), srv.cancelCtx)
	defer cancel(nil)

	errorCh := make(chan error, 4)
	ch1 := make(chan *RaftRequest, 1)
	ch2 := make(chan raftPendingResponsePayload, 1)
	ch3 := make(chan *RaftResponse, 1)
	go func() { errorCh <- srv.readRequestStep(ctx, stream, ch1) }()
	go func() { errorCh <- srv.handleRequestStep(ctx, ch1, ch2) }()
	go func() { errorCh <- srv.handleResponseStep(ctx, ch2, ch3) }()
	go func() { errorCh <- srv.sendResponseStep(ctx, stream, ch3) }()
	return <-errorCh
}

func (srv *raftServer) Stop() {
	srv.cancel()
}

func (srv *raftServer) Transport(clientManager grpcutil.ClientManager) RaftTransport {
	return newRaftServerTransport(srv, clientManager)
}

func (srv *raftServer) readRequestStep(ctx context.Context, stream grpc.BidiStreamingServer[RaftRequest, RaftResponse], out chan<- *RaftRequest) error {
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case out <- request:
		}
	}
}

func (srv *raftServer) handleRequestStep(ctx context.Context, in <-chan *RaftRequest, out chan<- raftPendingResponsePayload) error {
	type PendingRequest struct {
		writer        io.WriteCloser
		pendingChunks int
	}
	pending := map[uint64]PendingRequest{}
	defer func() {
		for _, pendingRequest := range pending {
			_ = pendingRequest.writer.Close()
		}
	}()

	for {
		var request *RaftRequest
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case request = <-in:
		}

		// chunks should be sent to the pending requests
		if payload, ok := request.Payload.(*RaftRequest_Chunk_); ok {
			pendingRequest, ok := pending[request.RequestId]
			if ok {
				pendingRequest.pendingChunks--
				_, err := pendingRequest.writer.Write(payload.Chunk.Data)
				if err != nil || pendingRequest.pendingChunks <= 0 {
					_ = pendingRequest.writer.Close()
					delete(pending, request.RequestId)
				}
			} else {
				log.Ctx(ctx).Error().Msg("databroker-raft-transport: dropping unmatched chunk")
			}
			continue
		}

		ch := make(chan raft.RPCResponse, 1)
		rpcRequest := raft.RPC{RespChan: ch}
		rpcHeader := raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersion(request.ProtocolVersion),
			ID:              request.ServerId,
			Addr:            request.ServerAddr,
		}

		switch payload := request.Payload.(type) {
		case *RaftRequest_AppendEntriesRequest_:
			command := &raft.AppendEntriesRequest{
				RPCHeader:         rpcHeader,
				Term:              payload.AppendEntriesRequest.Term,
				Leader:            payload.AppendEntriesRequest.Leader,
				PrevLogEntry:      payload.AppendEntriesRequest.PrevLogEntry,
				PrevLogTerm:       payload.AppendEntriesRequest.PrevLogTerm,
				Entries:           make([]*raft.Log, len(payload.AppendEntriesRequest.Entries)),
				LeaderCommitIndex: payload.AppendEntriesRequest.LeaderCommitIndex,
			}
			for i, e := range payload.AppendEntriesRequest.Entries {
				command.Entries[i] = &raft.Log{
					Index:      e.Index,
					Term:       e.Term,
					Type:       raft.LogType(e.LogType),
					Data:       e.Data,
					Extensions: e.Extensions,
					AppendedAt: e.AppendedAt.AsTime(),
				}
			}
			rpcRequest.Command = command
		case *RaftRequest_InstallSnapshotRequest_:
			command := &raft.InstallSnapshotRequest{
				RPCHeader:          rpcHeader,
				SnapshotVersion:    raft.SnapshotVersion(payload.InstallSnapshotRequest.SnapshotVersion),
				Term:               payload.InstallSnapshotRequest.Term,
				Leader:             payload.InstallSnapshotRequest.Leader,
				LastLogIndex:       payload.InstallSnapshotRequest.LastLogIndex,
				LastLogTerm:        payload.InstallSnapshotRequest.LastLogTerm,
				Peers:              payload.InstallSnapshotRequest.Peers,
				Configuration:      payload.InstallSnapshotRequest.Configuration,
				ConfigurationIndex: payload.InstallSnapshotRequest.ConfigurationIndex,
				Size:               payload.InstallSnapshotRequest.Size,
			}
			rpcRequest.Command = command
		case *RaftRequest_RequestPreVoteRequest_:
			command := &raft.RequestPreVoteRequest{
				RPCHeader:    rpcHeader,
				Term:         payload.RequestPreVoteRequest.Term,
				LastLogIndex: payload.RequestPreVoteRequest.LastLogIndex,
				LastLogTerm:  payload.RequestPreVoteRequest.LastLogTerm,
			}
			rpcRequest.Command = command
		case *RaftRequest_RequestVoteRequest_:
			command := &raft.RequestVoteRequest{
				RPCHeader:          rpcHeader,
				Term:               payload.RequestVoteRequest.Term,
				Candidate:          payload.RequestVoteRequest.Candidate,
				LastLogIndex:       payload.RequestVoteRequest.LastLogIndex,
				LastLogTerm:        payload.RequestVoteRequest.LastLogTerm,
				LeadershipTransfer: payload.RequestVoteRequest.LeadershipTransfer,
			}
			rpcRequest.Command = command
		case *RaftRequest_TimeoutNowRequest_:
			command := &raft.TimeoutNowRequest{
				RPCHeader: rpcHeader,
			}
			rpcRequest.Command = command
		default:
			ch <- raft.RPCResponse{
				Error: fmt.Errorf("unknown request payload type: %T", request.Payload),
			}
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case out <- raftPendingResponsePayload{request: request, ch: ch}:
			}
			continue
		}

		if request.ChunkCount > 0 {
			pr, pw := io.Pipe()
			pending[request.RequestId] = PendingRequest{
				writer:        pw,
				pendingChunks: int(request.ChunkCount),
			}
			rpcRequest.Reader = pr
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case srv.consumerCh <- rpcRequest:
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case out <- raftPendingResponsePayload{request: request, ch: ch}:
		}
	}
}

func (srv *raftServer) handleResponseStep(ctx context.Context, in <-chan raftPendingResponsePayload, out chan<- *RaftResponse) error {
	for {
		var pendingResponse raftPendingResponsePayload
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case pendingResponse = <-in:
		}

		var rpcResponse raft.RPCResponse
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case rpcResponse = <-pendingResponse.ch:
		}

		response := &RaftResponse{
			RequestId: pendingResponse.request.RequestId,
		}

		if rpcResponse.Error != nil {
			response.Payload = &RaftResponse_Error{
				Error: rpcResponse.Error.Error(),
			}
		} else {
			switch payload := rpcResponse.Response.(type) {
			case *raft.AppendEntriesResponse:
				response.ProtocolVersion = int32(payload.RPCHeader.ProtocolVersion)
				response.ServerId = payload.RPCHeader.ID
				response.ServerAddr = payload.RPCHeader.Addr
				response.Payload = &RaftResponse_AppendEntriesResponse_{
					AppendEntriesResponse: &RaftResponse_AppendEntriesResponse{
						Term:           payload.Term,
						LastLog:        payload.LastLog,
						Success:        payload.Success,
						NoRetryBackoff: payload.NoRetryBackoff,
					},
				}
			case *raft.InstallSnapshotResponse:
				response.ProtocolVersion = int32(payload.RPCHeader.ProtocolVersion)
				response.ServerId = payload.RPCHeader.ID
				response.ServerAddr = payload.RPCHeader.Addr
				response.Payload = &RaftResponse_InstallSnapshotResponse_{
					InstallSnapshotResponse: &RaftResponse_InstallSnapshotResponse{
						Term:    payload.Term,
						Success: payload.Success,
					},
				}
			case *raft.RequestPreVoteResponse:
				response.ProtocolVersion = int32(payload.RPCHeader.ProtocolVersion)
				response.ServerId = payload.RPCHeader.ID
				response.ServerAddr = payload.RPCHeader.Addr
				response.Payload = &RaftResponse_RequestPreVoteResponse_{
					RequestPreVoteResponse: &RaftResponse_RequestPreVoteResponse{
						Term:    payload.Term,
						Granted: payload.Granted,
					},
				}
			case *raft.RequestVoteResponse:
				response.ProtocolVersion = int32(payload.RPCHeader.ProtocolVersion)
				response.ServerId = payload.RPCHeader.ID
				response.ServerAddr = payload.RPCHeader.Addr
				response.Payload = &RaftResponse_RequestVoteResponse_{
					RequestVoteResponse: &RaftResponse_RequestVoteResponse{
						Term:    payload.Term,
						Peers:   payload.Peers,
						Granted: payload.Granted,
					},
				}
			case *raft.TimeoutNowResponse:
				response.ProtocolVersion = int32(payload.RPCHeader.ProtocolVersion)
				response.ServerId = payload.RPCHeader.ID
				response.ServerAddr = payload.RPCHeader.Addr
				response.Payload = &RaftResponse_TimeoutNowResponse_{
					TimeoutNowResponse: &RaftResponse_TimeoutNowResponse{},
				}
			default:
				response.Payload = &RaftResponse_Error{
					Error: fmt.Errorf("unknown response type: %T", rpcResponse.Response).Error(),
				}
			}
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case out <- response:
		}
	}
}

func (srv *raftServer) sendResponseStep(ctx context.Context, stream grpc.BidiStreamingServer[RaftRequest, RaftResponse], in <-chan *RaftResponse) error {
	for {
		var response *RaftResponse
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case response = <-in:
		}

		err := stream.Send(response)
		if err != nil {
			return err
		}
	}
}

type RaftTransport interface {
	raft.Transport
	raft.WithClose
	raft.WithPreVote
}

type raftServerTransport struct {
	srv           *raftServer
	clientManager grpcutil.ClientManager

	closeCtx context.Context
	close    context.CancelFunc

	nextRequestID atomic.Uint64
}

func newRaftServerTransport(srv *raftServer, clientManager grpcutil.ClientManager) *raftServerTransport {
	t := &raftServerTransport{
		srv:           srv,
		clientManager: clientManager,
	}
	t.closeCtx, t.close = context.WithCancel(srv.cancelCtx)
	t.nextRequestID.Store(cryptutil.NewRandomUInt64())
	return t
}

func (t *raftServerTransport) Close() error {
	t.close()
	return nil
}

func (t *raftServerTransport) Consumer() <-chan raft.RPC {
	return t.srv.consumerCh
}

func (t *raftServerTransport) LocalAddr() raft.ServerAddress {
	return t.srv.localServerAddress
}

func (t *raftServerTransport) AppendEntriesPipeline(id raft.ServerID, target raft.ServerAddress) (raft.AppendPipeline, error) {
	return nil, raft.ErrPipelineReplicationNotSupported
}

func (t *raftServerTransport) AppendEntries(id raft.ServerID, target raft.ServerAddress, args *raft.AppendEntriesRequest, resp *raft.AppendEntriesResponse) error {
	response, err := t.rpc(target, func(yield func(*RaftRequest) bool) {
		payload := &RaftRequest_AppendEntriesRequest_{
			AppendEntriesRequest: &RaftRequest_AppendEntriesRequest{
				Term:              args.Term,
				Leader:            args.Leader,
				PrevLogEntry:      args.PrevLogEntry,
				PrevLogTerm:       args.PrevLogTerm,
				Entries:           make([]*RaftRequest_Log, len(args.Entries)),
				LeaderCommitIndex: args.LeaderCommitIndex,
			},
		}
		for i, e := range args.Entries {
			payload.AppendEntriesRequest.Entries[i] = &RaftRequest_Log{
				Index:      e.Index,
				Term:       e.Term,
				LogType:    int32(e.Type),
				Data:       e.Data,
				Extensions: e.Extensions,
				AppendedAt: timestamppb.New(e.AppendedAt),
			}
		}
		yield(&RaftRequest{
			ProtocolVersion: int32(args.ProtocolVersion),
			ServerId:        []byte(id),
			ServerAddr:      []byte(target),
			ChunkCount:      0,
			Payload:         payload,
		})
	})
	if err != nil {
		return err
	}

	payload, ok := response.Payload.(*RaftResponse_AppendEntriesResponse_)
	if !ok {
		return fmt.Errorf("raft-server-transport: unexpected response payload type: %T", response.Payload)
	}

	*resp = raft.AppendEntriesResponse{
		RPCHeader: raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersion(response.ProtocolVersion),
			ID:              response.ServerId,
			Addr:            response.ServerAddr,
		},
		Term:           payload.AppendEntriesResponse.Term,
		LastLog:        payload.AppendEntriesResponse.LastLog,
		Success:        payload.AppendEntriesResponse.Success,
		NoRetryBackoff: payload.AppendEntriesResponse.NoRetryBackoff,
	}
	return nil
}

func (t *raftServerTransport) RequestPreVote(id raft.ServerID, target raft.ServerAddress, args *raft.RequestPreVoteRequest, resp *raft.RequestPreVoteResponse) error {
	response, err := t.rpc(target, func(yield func(*RaftRequest) bool) {
		yield(&RaftRequest{
			ProtocolVersion: int32(args.ProtocolVersion),
			ServerId:        []byte(id),
			ServerAddr:      []byte(target),
			ChunkCount:      0,
			Payload: &RaftRequest_RequestPreVoteRequest_{
				RequestPreVoteRequest: &RaftRequest_RequestPreVoteRequest{
					Term:         args.Term,
					LastLogIndex: args.LastLogIndex,
					LastLogTerm:  args.LastLogTerm,
				},
			},
		})
	})
	if err != nil {
		return err
	}

	payload, ok := response.Payload.(*RaftResponse_RequestPreVoteResponse_)
	if !ok {
		return fmt.Errorf("raft-server-transport: unexpected response payload type: %T", response.Payload)
	}

	*resp = raft.RequestPreVoteResponse{
		RPCHeader: raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersion(response.ProtocolVersion),
			ID:              response.ServerId,
			Addr:            response.ServerAddr,
		},
		Term:    payload.RequestPreVoteResponse.Term,
		Granted: payload.RequestPreVoteResponse.Granted,
	}
	return nil
}

func (t *raftServerTransport) RequestVote(id raft.ServerID, target raft.ServerAddress, args *raft.RequestVoteRequest, resp *raft.RequestVoteResponse) error {
	response, err := t.rpc(target, func(yield func(*RaftRequest) bool) {
		yield(&RaftRequest{
			ProtocolVersion: int32(args.ProtocolVersion),
			ServerId:        []byte(id),
			ServerAddr:      []byte(target),
			ChunkCount:      0,
			Payload: &RaftRequest_RequestVoteRequest_{
				RequestVoteRequest: &RaftRequest_RequestVoteRequest{
					Term:               args.Term,
					Candidate:          args.Candidate,
					LastLogIndex:       args.LastLogIndex,
					LastLogTerm:        args.LastLogTerm,
					LeadershipTransfer: args.LeadershipTransfer,
				},
			},
		})
	})
	if err != nil {
		return err
	}

	payload, ok := response.Payload.(*RaftResponse_RequestVoteResponse_)
	if !ok {
		return fmt.Errorf("raft-server-transport: unexpected response payload type: %T", response.Payload)
	}

	*resp = raft.RequestVoteResponse{
		RPCHeader: raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersion(response.ProtocolVersion),
			ID:              response.ServerId,
			Addr:            response.ServerAddr,
		},
		Term:    payload.RequestVoteResponse.Term,
		Peers:   payload.RequestVoteResponse.Peers,
		Granted: payload.RequestVoteResponse.Granted,
	}
	return nil
}

func (t *raftServerTransport) InstallSnapshot(id raft.ServerID, target raft.ServerAddress, args *raft.InstallSnapshotRequest, resp *raft.InstallSnapshotResponse, data io.Reader) error {
	const chunkSize = 4096

	response, err := t.rpc(target, func(yield func(*RaftRequest) bool) {
		chunkCount := args.Size / chunkSize
		if args.Size%chunkSize != 0 {
			chunkCount++
		}

		request := &RaftRequest{
			ProtocolVersion: int32(args.ProtocolVersion),
			ServerId:        []byte(id),
			ServerAddr:      []byte(target),
			ChunkCount:      uint64(chunkCount),
			Payload: &RaftRequest_InstallSnapshotRequest_{
				InstallSnapshotRequest: &RaftRequest_InstallSnapshotRequest{
					SnapshotVersion:    int32(args.SnapshotVersion),
					Term:               args.Term,
					Leader:             args.Leader,
					LastLogIndex:       args.LastLogIndex,
					LastLogTerm:        args.LastLogTerm,
					Peers:              args.Peers,
					Configuration:      args.Configuration,
					ConfigurationIndex: args.ConfigurationIndex,
					Size:               args.Size,
				},
			},
		}
		if !yield(request) {
			return
		}

		for remaining := int(args.Size); remaining > 0; {
			buf := make([]byte, min(remaining, chunkSize))
			n, err := io.ReadFull(data, buf)
			if err != nil {
				return
			}
			request = proto.CloneOf(request)
			request.ChunkCount = 0
			request.Payload = &RaftRequest_Chunk_{
				Chunk: &RaftRequest_Chunk{
					Data: buf[:n],
				},
			}
			if !yield(request) {
				return
			}
			remaining -= n
		}
	})
	if err != nil {
		return err
	}

	payload, ok := response.Payload.(*RaftResponse_InstallSnapshotResponse_)
	if !ok {
		return fmt.Errorf("raft-server-transport: unexpected response payload type: %T", response.Payload)
	}

	*resp = raft.InstallSnapshotResponse{
		RPCHeader: raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersion(response.ProtocolVersion),
			ID:              response.ServerId,
			Addr:            response.ServerAddr,
		},
		Term:    payload.InstallSnapshotResponse.Term,
		Success: payload.InstallSnapshotResponse.Success,
	}
	return nil
}

func (t *raftServerTransport) EncodePeer(_ raft.ServerID, addr raft.ServerAddress) []byte {
	return []byte(addr)
}

func (t *raftServerTransport) DecodePeer(peer []byte) raft.ServerAddress {
	return raft.ServerAddress(peer)
}

func (t *raftServerTransport) SetHeartbeatHandler(_ func(rpc raft.RPC)) {}

func (t *raftServerTransport) TimeoutNow(id raft.ServerID, target raft.ServerAddress, args *raft.TimeoutNowRequest, resp *raft.TimeoutNowResponse) error {
	response, err := t.rpc(target, func(yield func(*RaftRequest) bool) {
		yield(&RaftRequest{
			ProtocolVersion: int32(args.ProtocolVersion),
			ServerId:        []byte(id),
			ServerAddr:      []byte(target),
			ChunkCount:      0,
			Payload: &RaftRequest_TimeoutNowRequest_{
				TimeoutNowRequest: &RaftRequest_TimeoutNowRequest{},
			},
		})
	})
	if err != nil {
		return err
	}

	_, ok := response.Payload.(*RaftResponse_TimeoutNowResponse_)
	if !ok {
		return fmt.Errorf("raft-server-transport: unexpected response payload type: %T", response.Payload)
	}

	*resp = raft.TimeoutNowResponse{
		RPCHeader: raft.RPCHeader{
			ProtocolVersion: raft.ProtocolVersion(response.ProtocolVersion),
			ID:              response.ServerId,
			Addr:            response.ServerAddr,
		},
	}
	return nil
}

func (t *raftServerTransport) rpc(target raft.ServerAddress, requests iter.Seq[*RaftRequest]) (*RaftResponse, error) {
	ctx, cancel := context.WithCancel(t.closeCtx)
	defer cancel()

	ctx, clearTimeout := context.WithTimeout(ctx, t.srv.timeout)
	defer clearTimeout()

	client := NewDataBrokerServiceClient(t.clientManager.GetClient(string(target)))
	stream, err := client.Raft(ctx)
	if err != nil {
		return nil, err
	}

	requestID := t.nextRequestID.Add(1)
	for request := range requests {
		request.RequestId = requestID
		err = stream.Send(request)
		if err != nil {
			return nil, fmt.Errorf("raft-server-transport: error sending request: %w", err)
		}
	}

	response, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("raft-server-transport: error receiving response: %w", err)
	}

	if payload, ok := response.Payload.(*RaftResponse_Error); ok {
		return nil, fmt.Errorf("raft-server-transport: received error response: %s", payload.Error)
	}

	return response, nil
}
