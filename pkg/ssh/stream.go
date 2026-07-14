package ssh

import (
	"context"
	"fmt"
	"iter"
	stdslices "slices"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	datav3 "github.com/envoyproxy/go-control-plane/envoy/data/core/v3"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/pomerium/pomerium/pkg/ssh/common"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

const (
	MethodPublicKey           = "publickey"
	MethodKeyboardInteractive = "keyboard-interactive"

	ChannelTypeSession     = "session"
	ChannelTypeDirectTcpip = "direct-tcpip"

	ServiceConnection = "ssh-connection"
)

type KeyboardInteractiveQuerier interface {
	// Prompts the client and returns their responses to the given prompts.
	Prompt(ctx context.Context, prompts *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error)
}

type AuthMethodResponse struct {
	AllowMethod              bool
	NextRequiredAuthMethod   string
	NoFurtherMethodsRequired bool
	ContextUpdates           *extensions_ssh.AuthContext
}

func (r *AuthMethodResponse) Validate() {
	if r.AllowMethod {
		if r.NextRequiredAuthMethod == "" && !r.NoFurtherMethodsRequired {
			panic("invalid AuthMethodResponse: either NextRequiredAuthMethod or NoFurtherMethodsRequired must be set if AllowMethod is true")
		}
		if r.NextRequiredAuthMethod == MethodPublicKey {
			// There is currently no situation where we need to restart a successful publickey request, but it is not invalid.
			// If we ever need to do so, remove this check
			panic("invalid AuthMethodResponse: unexpected NextRequiredAuthMethod publickey when AllowMethod is true")
		}
	} else {
		if r.ContextUpdates != nil {
			panic("invalid AuthMethodResponse: ContextUpdates can only be set if AllowMethod is true")
		}
		if r.NoFurtherMethodsRequired {
			panic("invalid AuthMethodResponse: NoFurtherMethodsRequired can only be set if AllowMethod is true")
		}
	}
	if r.NextRequiredAuthMethod != "" {
		if r.NoFurtherMethodsRequired {
			panic("invalid AuthMethodResponse: NextRequiredAuthMethod and NoFurtherMethodsRequired are mutually exclusive")
		}
		switch r.NextRequiredAuthMethod {
		case MethodPublicKey:
		case MethodKeyboardInteractive:
		default:
			panic("invalid AuthMethodResponse: unknown auth method name: " + r.NextRequiredAuthMethod)
		}
	}
}

func (r *AuthMethodResponse) String() string {
	if !r.AllowMethod {
		if r.NextRequiredAuthMethod != "" {
			return fmt.Sprintf("unauthorized (retry: %s)", r.NextRequiredAuthMethod)
		}
		return "unauthorized"
	}
	if !r.NoFurtherMethodsRequired {
		return fmt.Sprintf("partially authorized (next: %s)", r.NextRequiredAuthMethod)
	}
	return fmt.Sprintf("authorized")
}

//go:generate go tool go.uber.org/mock/mockgen -typed -destination ./mock/mock_auth_interface.go . AuthInterface

type AuthInterface interface {
	HandlePublicKeyMethodRequest(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest, req *extensions_ssh.PublicKeyMethodRequest) (AuthMethodResponse, error)
	HandleKeyboardInteractiveMethodRequest(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest, req *extensions_ssh.KeyboardInteractiveMethodRequest, querier KeyboardInteractiveQuerier) (AuthMethodResponse, error)
	EvaluateDelayed(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest) error
	BuildTargetChannelFilters(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo, user api.UserRequest) (*corev3.SocketAddress, []*corev3.TypedExtensionConfig, error)
	GetSession(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo) (*session.Session, error)
	DeleteSession(ctx context.Context, streamInfo StreamInfo, authInfo StreamAuthInfo) error
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
	AccessRequestManager() api.AccessRequestManagerInterface
}

type ClusterStatsListener interface {
	HandleClusterStatsUpdate(*envoy_config_endpoint_v3.ClusterStats)
}

type EndpointDiscoveryInterface interface {
	PortForwardManager() *portforward.Manager
	UpdateClusterEndpoints(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{})
}

type StreamInfo struct {
	StreamID            uint64
	SourceAddress       string
	ChannelType         string
	InitialAuthComplete bool
}

// type StreamAuthInfo struct {
// 	PublicKey                  []byte
// 	PublicKeyAlg               string
// 	PublicKeyFingerprintSha256 []byte
// }

// func (i *StreamAuthInfo) Clone() StreamAuthInfo {
// 	clone := StreamAuthInfo{
// 		StreamID:                   i.StreamID,
// 		SourceAddress:              i.SourceAddress,
// 		ChannelType:                i.ChannelType,
// 		PublicKey: ,
// 		PublicKeyFingerprintSha256: i.PublicKeyFingerprintSha256,
// 		InitialAuthComplete:        i.InitialAuthComplete,
// 	}
// 	return clone
// }

// func (i *StreamAuthInfo) allMethodsValid() bool {
// 	return i.PublicKeyAllow.IsValid() && i.KeyboardInteractiveAllow.IsValid() && i.AccessRequestAllow.IsValid()
// }

type StreamAuthInfo interface {
	// Public key info
	GetPublicKey() []byte
	GetPublicKeyAlg() string
	GetPublicKeyFingerprintSha256() []byte // No formatting

	// Session and user IDs
	GetSessionId() string
	GetUserId() string
	GetSessionBindingId() string

	// Two person approval
	GetAccessRequestState() extensions_ssh.AccessRequestState
}

type StreamState struct {
	StreamInfo
	AuthContext            *extensions_ssh.AuthContext
	CurrentUser            api.UserRequest
	NextRequiredAuthMethod string
	DownstreamChannelInfo  *extensions_ssh.SSHDownstreamChannelInfo
}

type InternalChannelRequest struct {
	DownstreamChannelInfo *extensions_ssh.SSHDownstreamChannelInfo
	ChannelType           string
	Reply                 chan InternalChannelReply
}

type InternalChannelReply struct {
	StreamInfo  StreamInfo
	AuthInfo    StreamAuthInfo
	CurrentUser api.UserRequest
}

type HandoffRequest struct {
	User    api.UserRequest
	PtyInfo api.SSHPtyInfo
	Reply   chan *extensions_ssh.SSHChannelControlAction
	Err     chan error
}

// StreamHandler handles a single SSH stream
type StreamHandler struct {
	auth                    AuthInterface
	discovery               EndpointDiscoveryInterface
	cliCtrl                 cli.InternalCLIController
	config                  *config.Config
	downstream              *extensions_ssh.DownstreamConnectEvent
	writeC                  chan *extensions_ssh.ServerMessage
	readC                   chan *extensions_ssh.ClientMessage
	reauthC                 chan struct{}
	internalChannelRequestC chan InternalChannelRequest
	handoffRequestC         chan HandoffRequest
	terminateFunc           context.CancelCauseFunc

	close        func()
	runOnce      bool
	terminateErr error

	expectingInternalChannel atomic.Bool
	internalSession          atomic.Pointer[ChannelHandler]

	// Internal data models
	channelModel    *models.ChannelModel
	routeModel      *models.RouteModel
	permissionModel *models.PermissionModel

	arbitrationAuthorizedRoutesMu              sync.Mutex
	arbitrationAuthorizedRoutes                []common.RouteInfo
	arbitrationAuthorizedRoutesInitialSyncDone chan struct{}
}

// PermissionDataModel implements StreamHandlerInterface.
func (sh *StreamHandler) PermissionDataModel() *models.PermissionModel {
	return sh.permissionModel
}

// RouteDataModel implements StreamHandlerInterface.
func (sh *StreamHandler) RouteDataModel() *models.RouteModel {
	return sh.routeModel
}

// ChannelDataModel implements StreamHandlerInterface.
func (sh *StreamHandler) ChannelDataModel() *models.ChannelModel {
	return sh.channelModel
}

func NewStreamHandler(
	auth AuthInterface,
	discovery EndpointDiscoveryInterface,
	cliCtrl cli.InternalCLIController,
	cfg *config.Config,
	downstream *extensions_ssh.DownstreamConnectEvent,
	onClosed func(),
) *StreamHandler {
	writeC := make(chan *extensions_ssh.ServerMessage, 32)
	sh := &StreamHandler{
		auth:                    auth,
		discovery:               discovery,
		cliCtrl:                 cliCtrl,
		config:                  cfg,
		downstream:              downstream,
		writeC:                  writeC,
		readC:                   make(chan *extensions_ssh.ClientMessage, 32),
		reauthC:                 make(chan struct{}),
		internalChannelRequestC: make(chan InternalChannelRequest, 1),
		handoffRequestC:         make(chan HandoffRequest, 1),
		close: func() {
			onClosed()
			close(writeC)
		},
		channelModel:    models.NewChannelModel(),
		routeModel:      models.NewRouteModel(cliCtrl.EventHandlers().RouteDataModelEventHandlers),
		permissionModel: models.NewPermissionModel(),
		arbitrationAuthorizedRoutesInitialSyncDone: make(chan struct{}),
	}
	return sh
}

// OnClusterEndpointsUpdated implements portforward.UpdateListener.
func (sh *StreamHandler) OnClusterEndpointsUpdated(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{}) {
	sh.discovery.UpdateClusterEndpoints(added, removed)
	sh.routeModel.HandleClusterEndpointsUpdate(added, removed)
	sh.permissionModel.HandleClusterEndpointsUpdate(added, removed)
}

// OnPermissionsUpdated implements portforward.UpdateListener.
func (sh *StreamHandler) OnPermissionsUpdated(permissions []portforward.Permission) {
	sh.permissionModel.HandlePermissionsUpdate(permissions)
}

// OnRoutesUpdated implements portforward.UpdateListener.
func (sh *StreamHandler) OnRoutesUpdated(routes []common.RouteInfo) {
	sh.routeModel.HandleRoutesUpdate(routes)
}

func (sh *StreamHandler) OnClusterHealthUpdate(_ context.Context, event *datav3.HealthCheckEvent) {
	sh.routeModel.HandleClusterHealthUpdate(event)
}

func (sh *StreamHandler) UpdateArbitrationAuthorizedRoutes(routes []common.RouteInfo) {
	sh.arbitrationAuthorizedRoutesMu.Lock()
	defer sh.arbitrationAuthorizedRoutesMu.Unlock()

	select {
	case <-sh.arbitrationAuthorizedRoutesInitialSyncDone:
	default:
		close(sh.arbitrationAuthorizedRoutesInitialSyncDone)
	}
	sh.arbitrationAuthorizedRoutes = stdslices.Clone(routes)
}

func (sh *StreamHandler) GetArbitrationAuthorizedRoutes(ctx context.Context) []common.RouteInfo {
	select {
	case <-sh.arbitrationAuthorizedRoutesInitialSyncDone:
	case <-ctx.Done():
		return nil
	}

	sh.arbitrationAuthorizedRoutesMu.Lock()
	defer sh.arbitrationAuthorizedRoutesMu.Unlock()
	return stdslices.Clone(sh.arbitrationAuthorizedRoutes)
}

func (sh *StreamHandler) AccessRequestManager() api.AccessRequestManagerInterface {
	return sh.auth.AccessRequestManager()
}

func (sh *StreamHandler) Terminate(err error) {
	sh.terminateErr = err
	if sh.terminateFunc != nil {
		sh.terminateFunc(err)
	}
}

func (sh *StreamHandler) Close() {
	sh.close()
}

func (sh *StreamHandler) IsExpectingInternalChannel() bool {
	return sh.expectingInternalChannel.Load()
}

func (sh *StreamHandler) ReadC() chan<- *extensions_ssh.ClientMessage {
	return sh.readC
}

func (sh *StreamHandler) WriteC() <-chan *extensions_ssh.ServerMessage {
	return sh.writeC
}

// Reauth blocks until authorization policy is reevaluated.
func (sh *StreamHandler) Reauth() {
	sh.reauthC <- struct{}{}
}

func (sh *StreamHandler) periodicReauth() (cancel func()) {
	t := time.NewTicker(1 * time.Minute)
	go func() {
		for range t.C {
			sh.Reauth()
		}
	}()
	return t.Stop
}

// Prompt implements KeyboardInteractiveQuerier.
func (sh *StreamHandler) Prompt(ctx context.Context, prompts *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
	sh.sendInfoPrompts(prompts)
	select {
	case <-ctx.Done():
		// Important: ctx is expected to be canceled on terminate
		// TODO sanity check this
		return nil, context.Cause(ctx)
	case req := <-sh.readC:
		switch msg := req.Message.(type) {
		case *extensions_ssh.ClientMessage_InfoResponse:
			if msg.InfoResponse.Method != MethodKeyboardInteractive {
				return nil, status.Errorf(codes.Internal, "received invalid info response")
			}
			r, _ := msg.InfoResponse.Response.UnmarshalNew()
			respInfo, ok := r.(*extensions_ssh.KeyboardInteractiveInfoPromptResponses)
			if !ok {
				return nil, status.Errorf(codes.InvalidArgument, "received invalid prompt response")
			}
			return respInfo, nil
		default:
			return nil, status.Errorf(codes.InvalidArgument, "received invalid message, expecting info response")
		}
	}
}

func (sh *StreamHandler) Run(ctx context.Context) error {
	if sh.runOnce {
		panic("Run called twice")
	}
	sh.runOnce = true
	if sh.terminateErr != nil {
		return sh.terminateErr
	}
	ctx, sh.terminateFunc = context.WithCancelCause(ctx)

	state := &StreamState{
		NextRequiredAuthMethod: MethodPublicKey,
		StreamInfo: StreamInfo{
			StreamID:      sh.downstream.StreamId,
			SourceAddress: sh.downstream.SourceAddress.GetSocketAddress().GetAddress(),
		},
	}
	cancelReauth := sh.periodicReauth()
	defer cancelReauth()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-sh.reauthC:
			if err := sh.reauth(ctx, state); err != nil {
				return err
			}
		case req := <-sh.readC:
			switch req := req.Message.(type) {
			case *extensions_ssh.ClientMessage_Event:
				switch event := req.Event.Event.(type) {
				case *extensions_ssh.StreamEvent_DownstreamConnected:
					// this was already received as the first message in the stream
					return status.Errorf(codes.Internal, "received duplicate downstream connected event")
				case *extensions_ssh.StreamEvent_UpstreamConnected:
					log.Ctx(ctx).Debug().
						Msg("ssh: upstream connected")
				case *extensions_ssh.StreamEvent_DownstreamDisconnected:
					log.Ctx(ctx).Debug().
						Uint64("stream-id", sh.downstream.StreamId).
						Str("reason", event.DownstreamDisconnected.Reason).
						Msg("ssh: downstream disconnected")
				case *extensions_ssh.StreamEvent_ChannelEvent:
					sh.handleChannelEvent(event.ChannelEvent)
				case nil:
					return status.Errorf(codes.Internal, "received invalid event")
				}
			case *extensions_ssh.ClientMessage_AuthRequest:
				if err := sh.handleAuthRequest(ctx, state, req.AuthRequest); err != nil {
					return err
				}
			case *extensions_ssh.ClientMessage_GlobalRequest:
				if err := sh.handleGlobalRequest(ctx, state, req.GlobalRequest); err != nil {
					return err
				}
			default:
				return status.Errorf(codes.Internal, "received invalid client message type %#T", req)
			}
		case c := <-sh.internalChannelRequestC:
			sh.handleInternalChannelRequest(state, c)
		case req := <-sh.handoffRequestC:
			sh.handleHandoffRequest(ctx, state, req)
		}
	}
}

func (sh *StreamHandler) handleHandoffRequest(ctx context.Context, state *StreamState, req HandoffRequest) {
	lg := log.Ctx(ctx).With().
		Str("prevUsername", state.CurrentUser.Username()).
		Str("prevHostname", state.CurrentUser.Hostname()).
		Str("newUsername", req.User.Username()).
		Str("newHostname", req.User.Hostname()).
		Logger()

	lg.Debug().Msg("ssh: processing user update for handoff request")

	// state.CurrentUser will start with a non-empty username, and an empty
	// hostname. The goal here is to "promote" the current user into the requested
	// user by making sure the username matches, then setting the hostname to the
	// new non-empty hostname from the request.
	//
	// If PromoteFrom() succeeds, then both pendingUser and req.User will become
	// identical. But we don't want to mutate state.CurrentUser yet in case
	// auth evaluation fails. We also don't want to run the auth evaluation if
	// the new user would be invalid. So PromoteFrom is run against a copy of
	// state.CurrentUser, then it is applied only if auth succeeds.

	pendingUser := state.CurrentUser
	if err := pendingUser.PromoteFrom(req.User); err != nil {
		req.Err <- status.Error(codes.InvalidArgument, err.Error())
		return
	}
	err := sh.auth.EvaluateDelayed(ctx, state.StreamInfo, state.AuthContext, pendingUser)
	if err != nil {
		lg.Debug().Err(err).Msg("ssh: handoff request denied")
		req.Err <- status.Error(codes.PermissionDenied, err.Error())
		return
	}
	state.CurrentUser = pendingUser
	lg.Debug().Msg("ssh: user updated successfully; initiating handoff to upstream")

	addr, filters, err := sh.auth.BuildTargetChannelFilters(ctx, state.StreamInfo, state.AuthContext, state.CurrentUser)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to build extensions for filters")
		filters = []*corev3.TypedExtensionConfig{}
	}
	req.Reply <- buildHandoffAction(state, req.PtyInfo, addr, filters)
}

func (sh *StreamHandler) handleInternalChannelRequest(state *StreamState, c InternalChannelRequest) {
	if !sh.expectingInternalChannel.Load() {
		panic("bug: unexpected internal channel request")
	}
	state.DownstreamChannelInfo = c.DownstreamChannelInfo
	state.ChannelType = c.ChannelType
	c.Reply <- InternalChannelReply{
		StreamInfo:  state.StreamInfo,
		AuthInfo:    proto.CloneOf(state.AuthContext),
		CurrentUser: state.CurrentUser,
	}
}

func (sh *StreamHandler) handleChannelEvent(event *extensions_ssh.ChannelEvent) {
	sh.channelModel.HandleEvent(event)
}

func (sh *StreamHandler) handleGlobalRequest(ctx context.Context, state *StreamState, globalRequest *extensions_ssh.GlobalRequest) error {
	streamID := state.StreamID
	switch request := globalRequest.Request.(type) {
	case *extensions_ssh.GlobalRequest_TcpipForwardRequest:
		if !state.InitialAuthComplete {
			return status.Errorf(codes.InvalidArgument, "cannot request port-forward before auth is complete")
		}
		reqHost := request.TcpipForwardRequest.RemoteAddress
		reqPort := request.TcpipForwardRequest.RemotePort
		log.Ctx(ctx).Debug().
			Uint64("stream-id", streamID).
			Str("host", reqHost).
			Msg("got tcpip-forward request")

		serverPort, err := sh.discovery.PortForwardManager().AddPermission(reqHost, reqPort)
		if err != nil {
			log.Ctx(ctx).Debug().
				Uint64("stream-id", streamID).
				Err(err).
				Msg("sending global request failure")
			sh.sendGlobalRequestResponse(&extensions_ssh.GlobalRequestResponse{
				Success:      false,
				DebugMessage: err.Error(),
			})
			return nil
		}

		log.Ctx(ctx).Debug().
			Uint64("stream-id", streamID).
			Msg("sending global request success")

		// https://datatracker.ietf.org/doc/html/rfc4254#section-7.1
		if globalRequest.WantReply && reqPort == 0 {
			sh.sendGlobalRequestResponse(&extensions_ssh.GlobalRequestResponse{
				Success: true,
				Response: &extensions_ssh.GlobalRequestResponse_TcpipForwardResponse{
					TcpipForwardResponse: &extensions_ssh.TcpipForwardResponse{
						ServerPort: serverPort.Value,
					},
				},
			})
		}

		return nil
	case *extensions_ssh.GlobalRequest_CancelTcpipForwardRequest:
		if !state.InitialAuthComplete {
			return status.Errorf(codes.InvalidArgument, "cannot request port-forward before auth is complete")
		}
		err := sh.discovery.PortForwardManager().RemovePermission(
			request.CancelTcpipForwardRequest.RemoteAddress,
			request.CancelTcpipForwardRequest.RemotePort)
		if err != nil {
			sh.sendGlobalRequestResponse(&extensions_ssh.GlobalRequestResponse{
				Success:      false,
				DebugMessage: err.Error(),
			})
		} else if globalRequest.WantReply {
			sh.sendGlobalRequestResponse(&extensions_ssh.GlobalRequestResponse{
				Success: true,
			})
		}
		return nil
	default:
		return status.Errorf(codes.Unimplemented, "received unknown global request")
	}
}

func (sh *StreamHandler) sendGlobalRequestResponse(response *extensions_ssh.GlobalRequestResponse) {
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_GlobalRequestResponse{
			GlobalRequestResponse: response,
		},
	}
}

func (sh *StreamHandler) ServeChannel(
	stream extensions_ssh.StreamManagement_ServeChannelServer,
	metadata *extensions_ssh.FilterMetadata,
) error {
	// The first channel message on this stream should be a ChannelOpen
	channelOpen, err := stream.Recv()
	if err != nil {
		return err
	}
	rawMsg, ok := channelOpen.GetMessage().(*extensions_ssh.ChannelMessage_RawBytes)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "first channel message was not ChannelOpen")
	}
	var msg ChannelOpenMsg
	if err := gossh.Unmarshal(rawMsg.RawBytes.GetValue(), &msg); err != nil {
		return status.Errorf(codes.InvalidArgument, "first channel message was not ChannelOpen")
	}

	downstreamInfo := &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               msg.ChanType,
		DownstreamChannelId:       msg.PeersID,
		InternalUpstreamChannelId: metadata.ChannelId,
		InitialWindowSize:         msg.PeersWindow,
		MaxPacketSize:             msg.MaxPacketSize,
	}
	infoC := make(chan InternalChannelReply, 1)
	sh.internalChannelRequestC <- InternalChannelRequest{
		DownstreamChannelInfo: proto.CloneOf(downstreamInfo),
		ChannelType:           msg.ChanType,
		Reply:                 infoC,
	}
	select {
	case reply := <-infoC:
		reply.StreamInfo.ChannelType = msg.ChanType
		if reply.CurrentUser.Hostname() != "" {
			panic("bug: current hostname is not empty")
		}
		currentUsername := reply.CurrentUser.Username()
		channel := NewChannelImpl(
			newStreamHandlerInterfaceImpl(sh, currentUsername, downstreamInfo.DownstreamChannelId, reply.StreamInfo, reply.AuthInfo),
			stream, downstreamInfo)
		switch msg.ChanType {
		case ChannelTypeSession:
			ch := NewChannelHandler(channel, sh.cliCtrl, sh.config)
			if !sh.internalSession.CompareAndSwap(nil, ch) {
				return channel.SendMessage(ChannelOpenFailureMsg{
					PeersID: downstreamInfo.DownstreamChannelId,
					Reason:  Prohibited,
					Message: "multiple concurrent internal session channels not supported",
				})
			}
			if err := channel.SendMessage(ChannelOpenConfirmMsg{
				PeersID:       downstreamInfo.DownstreamChannelId,
				MyID:          downstreamInfo.InternalUpstreamChannelId,
				MyWindow:      ChannelWindowSize,
				MaxPacketSize: ChannelMaxPacket,
			}); err != nil {
				return err
			}

			err := ch.Run(stream.Context(), metadata.ModeHint)
			sh.internalSession.Store(nil)
			return err
		case ChannelTypeDirectTcpip:
			if !sh.config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHAllowDirectTcpip) {
				return status.Errorf(codes.Unavailable, "direct-tcpip channels are not enabled")
			}
			var subMsg ChannelOpenDirectMsg
			if err := gossh.Unmarshal(msg.TypeSpecificData, &subMsg); err != nil {
				return err
			}
			action, err := sh.RequestHandoff(stream.Context(), currentUsername, subMsg.DestAddr, nil)
			if err != nil {
				return err
			}
			return channel.SendControlAction(action)
		default:
			return status.Errorf(codes.InvalidArgument, "unexpected channel type in ChannelOpen message: %s", msg.ChanType)
		}
	case <-stream.Context().Done():
		return context.Cause(stream.Context())
	}
}

func (sh *StreamHandler) handleAuthRequest(ctx context.Context, state *StreamState, req *extensions_ssh.AuthenticationRequest) error {
	if req.Protocol != "ssh" {
		return status.Errorf(codes.InvalidArgument, "invalid protocol: %s", req.Protocol)
	}
	if req.Service != ServiceConnection {
		return status.Errorf(codes.InvalidArgument, "invalid service: %s", req.Service)
	}
	if req.AuthMethod != state.NextRequiredAuthMethod {
		return status.Errorf(codes.InvalidArgument, "unexpected auth method: %s", req.AuthMethod)
	}

	if err := state.CurrentUser.SetOrCheckEqual(req.Username, req.Hostname); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	log.Ctx(ctx).Debug().
		Str("method", req.AuthMethod).
		Str("username", state.CurrentUser.Username()).
		Str("hostname", state.CurrentUser.Hostname()).
		Msg("ssh: handling auth request")

	var response AuthMethodResponse
	switch req.AuthMethod {
	case MethodPublicKey:
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		pubkeyReq, ok := methodReq.(*extensions_ssh.PublicKeyMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid public key method request type")
		}

		var err error
		response, err = sh.auth.HandlePublicKeyMethodRequest(ctx, state.StreamInfo, state.AuthContext, state.CurrentUser, pubkeyReq)
		if err != nil {
			return err
		}
	case MethodKeyboardInteractive:
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		kbiReq, ok := methodReq.(*extensions_ssh.KeyboardInteractiveMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid keyboard-interactive method request type")
		}
		var err error
		response, err = sh.auth.HandleKeyboardInteractiveMethodRequest(ctx, state.StreamInfo, state.AuthContext, state.CurrentUser, kbiReq, sh)
		if err != nil {
			return err
		}
	default:
		return status.Errorf(codes.Internal, "bug: server requested an unsupported auth method %q", req.AuthMethod)
	}
	if response.ContextUpdates != nil {
		if state.AuthContext == nil {
			state.AuthContext = &extensions_ssh.AuthContext{}
		}
		proto.Merge(state.AuthContext, response.ContextUpdates)
	}
	state.NextRequiredAuthMethod = response.NextRequiredAuthMethod

	log.Ctx(ctx).Debug().
		Str("method", req.AuthMethod).
		Bool("method-allowed", response.AllowMethod).
		Str("methods-remaining", state.NextRequiredAuthMethod).
		Msg("ssh: auth request complete")

	if response.AllowMethod && state.NextRequiredAuthMethod == "" {
		// If this method was allowed and there are no methods remaining, auth is
		// successful
		state.InitialAuthComplete = true
		log.Ctx(ctx).Debug().Msg("ssh: all methods valid, sending allow response")
		sh.sendAllowResponse(ctx, state)
	} else {
		log.Ctx(ctx).Debug().Msg("ssh: unauthenticated methods remain, sending deny response")
		sh.sendDenyResponseWithRemainingMethods(response.AllowMethod, state)
	}
	return nil
}

func (sh *StreamHandler) reauth(ctx context.Context, state *StreamState) error {
	if !state.InitialAuthComplete {
		return nil
	}
	err := sh.auth.EvaluateDelayed(ctx, state.StreamInfo, state.AuthContext, state.CurrentUser)
	if err != nil {
		return err
	}
	return nil
}

func buildHandoffAction(state *StreamState, ptyInfo api.SSHPtyInfo, addr *corev3.SocketAddress, filters []*corev3.TypedExtensionConfig) *extensions_ssh.SSHChannelControlAction {
	upstreamAllow := buildUpstreamAllowResponse(state, addr, filters)
	var downstreamPtyInfo *extensions_ssh.SSHDownstreamPTYInfo
	if ptyInfo != nil {
		downstreamPtyInfo = &extensions_ssh.SSHDownstreamPTYInfo{
			TermEnv:      ptyInfo.GetTermEnv(),
			WidthColumns: ptyInfo.GetWidthColumns(),
			HeightRows:   ptyInfo.GetHeightRows(),
			WidthPx:      ptyInfo.GetWidthPx(),
			HeightPx:     ptyInfo.GetHeightPx(),
			Modes:        ptyInfo.GetModes(),
		}
	}
	action := &extensions_ssh.SSHChannelControlAction{
		Action: &extensions_ssh.SSHChannelControlAction_HandOff{
			HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
				DownstreamChannelInfo: state.DownstreamChannelInfo,
				DownstreamPtyInfo:     downstreamPtyInfo,
				UpstreamAuth:          upstreamAllow,
			},
		},
	}
	return action
}

func (sh *StreamHandler) AllSSHRoutes() iter.Seq[*config.Policy] {
	return func(yield func(*config.Policy) bool) {
		for route := range sh.config.Options.GetAllPolicies() {
			if route.IsSSH() {
				if !yield(route) {
					return
				}
			}
		}
	}
}

func (sh *StreamHandler) RequestHandoff(ctx context.Context, username, hostname string, ptyInfo api.SSHPtyInfo) (*extensions_ssh.SSHChannelControlAction, error) {
	replyC := make(chan *extensions_ssh.SSHChannelControlAction, 1)
	errC := make(chan error, 1)
	user, err := api.NewUserRequest(username, hostname)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	sh.handoffRequestC <- HandoffRequest{
		User:    user,
		PtyInfo: ptyInfo,
		Reply:   replyC,
		Err:     errC,
	}

	select {
	case reply := <-replyC:
		return reply, nil
	case err := <-errC:
		return nil, err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

// PortForwardManager implements StreamHandlerInterface.
// This is used by internal channels to add additional update listeners.
func (sh *StreamHandler) PortForwardManager() *portforward.Manager {
	return sh.discovery.PortForwardManager()
}

func (sh *StreamHandler) sendDenyResponseWithRemainingMethods(partial bool, state *StreamState) {
	var methods []string
	// empty string is not a valid method, it signals lack of next method
	if state.NextRequiredAuthMethod != "" {
		methods = append(methods, state.NextRequiredAuthMethod)
	}
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Deny{
					Deny: &extensions_ssh.DenyResponse{
						Partial: partial,
						Methods: methods,
					},
				},
			},
		},
	}
}

func (sh *StreamHandler) sendAllowResponse(ctx context.Context, state *StreamState) {
	var allow *extensions_ssh.AllowResponse
	if !state.CurrentUser.Valid() {
		panic("bug: current user invalid")
	}
	if state.CurrentUser.Hostname() == "" {
		sh.expectingInternalChannel.Store(true)
		allow = buildInternalAllowResponse(state)
	} else {
		addr, filters, err := sh.auth.BuildTargetChannelFilters(ctx, state.StreamInfo, state.AuthContext, state.CurrentUser)
		if err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to build channel filters")
			filters = []*corev3.TypedExtensionConfig{}
		}
		allow = buildUpstreamAllowResponse(state, addr, filters)
	}

	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Allow{
					Allow: allow,
				},
			},
		},
	}
}

func (sh *StreamHandler) sendInfoPrompts(prompts *extensions_ssh.KeyboardInteractiveInfoPrompts) {
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_InfoRequest{
					InfoRequest: &extensions_ssh.InfoRequest{
						Method:  MethodKeyboardInteractive,
						Request: protoutil.NewAny(prompts),
					},
				},
			},
		},
	}
}

func buildUpstreamAllowResponse(
	state *StreamState,
	address *corev3.SocketAddress,
	filters []*corev3.TypedExtensionConfig,
) *extensions_ssh.AllowResponse {
	authContext := proto.CloneOf(state.AuthContext)
	now := time.Now()
	certOptions := &extensions_ssh.CertificateOptions{
		PermitPortForwarding:  true,
		PermitAgentForwarding: true,
		PermitX11Forwarding:   true,
		PermitPty:             true,
		PermitUserRc:          true,
		// These timestamps are just for the temporary certificate and are only
		// checked by the upstream at the time of login. The durations aren't
		// particularly important and don't correspond to pomerium session
		// validity. The temporary certificates are only used for this connection
		// and are never shared with the downstream.
		ValidStartTime: timestamppb.New(now.Add(-1 * time.Minute)),
		ValidEndTime:   timestamppb.New(now.Add(1 * time.Hour)),
	}
	return &extensions_ssh.AllowResponse{
		LoginName:   state.CurrentUser.Username(),
		AuthContext: authContext,
		Target: &extensions_ssh.AllowResponse_Upstream{
			Upstream: &extensions_ssh.UpstreamTarget{
				Hostname:           state.CurrentUser.Hostname(),
				Address:            address,
				DirectTcpip:        state.ChannelType == ChannelTypeDirectTcpip,
				ChannelFilters:     filters,
				CertificateOptions: certOptions,
			},
		},
	}
}

func buildInternalAllowResponse(state *StreamState) *extensions_ssh.AllowResponse {
	return &extensions_ssh.AllowResponse{
		LoginName:   state.CurrentUser.Username(),
		AuthContext: state.AuthContext,
		Target: &extensions_ssh.AllowResponse_Internal{
			Internal: &extensions_ssh.InternalTarget{
				SetMetadata: &corev3.Metadata{
					TypedFilterMetadata: map[string]*anypb.Any{
						"com.pomerium.ssh": protoutil.NewAny(&extensions_ssh.FilterMetadata{
							StreamId: state.StreamID,
						}),
					},
				},
			},
		},
	}
}

type streamHandlerInterfaceImpl struct {
	*StreamHandler
	username            string
	downstreamChannelID uint32
	streamInfo          StreamInfo
	authInfo            StreamAuthInfo
}

// Returns an api.StreamHandlerInterface given a StreamHandler along with extra
// fields contained in the StreamState which are needed to implement this
// interface. The StreamState is not stored in the StreamHandler, so it cannot
// implement this interface itself.
func newStreamHandlerInterfaceImpl(sh *StreamHandler, username string, downstreamChannelID uint32, streamInfo StreamInfo, authInfo StreamAuthInfo) api.StreamHandlerInterface {
	return &streamHandlerInterfaceImpl{
		StreamHandler:       sh,
		username:            username,
		downstreamChannelID: downstreamChannelID,
		streamInfo:          streamInfo,
		authInfo:            authInfo,
	}
}

// DownstreamChannelID implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) DownstreamChannelID() uint32 {
	return si.downstreamChannelID
}

// DownstreamSourceAddress implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) DownstreamSourceAddress() string {
	return si.streamInfo.SourceAddress
}

// DownstreamPublicKeyFingerprint implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) DownstreamPublicKeyFingerprint() []byte {
	return si.authInfo.GetPublicKeyFingerprintSha256()
}

// Username implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) Username() string {
	return si.username
}

// GetSession implements StreamHandlerInterface
func (si *streamHandlerInterfaceImpl) GetSession(ctx context.Context) (*session.Session, error) {
	return si.auth.GetSession(ctx, si.streamInfo, si.authInfo)
}

// DeleteSession implements StreamHandlerInterface
func (si *streamHandlerInterfaceImpl) DeleteSession(ctx context.Context) error {
	return si.auth.DeleteSession(ctx, si.streamInfo, si.authInfo)
}
