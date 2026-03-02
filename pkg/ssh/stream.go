package ssh

import (
	"context"
	"iter"
	"reflect"
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

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/slices"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
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

type AuthMethodResponse[T any] struct {
	Allow                    *T
	RequireAdditionalMethods []string
}

type (
	PublicKeyAuthMethodResponse           = AuthMethodResponse[extensions_ssh.PublicKeyAllowResponse]
	KeyboardInteractiveAuthMethodResponse = AuthMethodResponse[extensions_ssh.KeyboardInteractiveAllowResponse]
)

//go:generate go tool -modfile ../../internal/tools/go.mod go.uber.org/mock/mockgen -typed -destination ./mock/mock_auth_interface.go . AuthInterface

type AuthInterface interface {
	HandlePublicKeyMethodRequest(ctx context.Context, info StreamAuthInfo, user api.UserRequest, req *extensions_ssh.PublicKeyMethodRequest) (PublicKeyAuthMethodResponse, error)
	HandleKeyboardInteractiveMethodRequest(ctx context.Context, info StreamAuthInfo, user api.UserRequest, req *extensions_ssh.KeyboardInteractiveMethodRequest, querier KeyboardInteractiveQuerier) (KeyboardInteractiveAuthMethodResponse, error)
	EvaluateDelayed(ctx context.Context, info StreamAuthInfo, user api.UserRequest) error
	GetSession(ctx context.Context, info StreamAuthInfo) (*session.Session, error)
	DeleteSession(ctx context.Context, info StreamAuthInfo) error
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
}

type ClusterStatsListener interface {
	HandleClusterStatsUpdate(*envoy_config_endpoint_v3.ClusterStats)
}

type EndpointDiscoveryInterface interface {
	PortForwardManager() *portforward.Manager
	UpdateClusterEndpoints(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{})
}

type AuthMethodValue[T interface {
	comparable
	proto.Message
}] struct {
	attempted bool
	Value     T
}

func (v *AuthMethodValue[T]) Update(value T) {
	v.attempted = true
	v.Value = value
}

func (v *AuthMethodValue[T]) IsValid() bool {
	if v.attempted {
		// method was attempted - valid iff there is a value
		return !reflect.ValueOf(v.Value).IsNil()
	}
	return true // method was not attempted - valid
}

func (v *AuthMethodValue[T]) Clone() AuthMethodValue[T] {
	return AuthMethodValue[T]{
		attempted: v.attempted,
		Value:     proto.CloneOf(v.Value),
	}
}

type StreamAuthInfo struct {
	StreamID                   uint64
	SourceAddress              string
	ChannelType                string
	PublicKeyFingerprintSha256 []byte
	PublicKeyAllow             AuthMethodValue[*extensions_ssh.PublicKeyAllowResponse]
	KeyboardInteractiveAllow   AuthMethodValue[*extensions_ssh.KeyboardInteractiveAllowResponse]
	InitialAuthComplete        bool
}

func (i *StreamAuthInfo) Clone() StreamAuthInfo {
	clone := StreamAuthInfo{
		StreamID:                   i.StreamID,
		SourceAddress:              i.SourceAddress,
		ChannelType:                i.ChannelType,
		PublicKeyFingerprintSha256: i.PublicKeyFingerprintSha256,
		PublicKeyAllow:             i.PublicKeyAllow.Clone(),
		KeyboardInteractiveAllow:   i.KeyboardInteractiveAllow.Clone(),
		InitialAuthComplete:        i.InitialAuthComplete,
	}
	return clone
}

func (i *StreamAuthInfo) allMethodsValid() bool {
	return i.PublicKeyAllow.IsValid() && i.KeyboardInteractiveAllow.IsValid()
}

type StreamState struct {
	StreamAuthInfo
	CurrentUser                     api.UserRequest
	RemainingUnauthenticatedMethods []string
	DownstreamChannelInfo           *extensions_ssh.SSHDownstreamChannelInfo
}

type InternalChannelRequest struct {
	DownstreamChannelInfo *extensions_ssh.SSHDownstreamChannelInfo
	ChannelType           string
	Reply                 chan InternalChannelReply
}

type InternalChannelReply struct {
	StreamAuthInfo
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
	terminateC              chan error
	internalChannelRequestC chan InternalChannelRequest
	handoffRequestC         chan HandoffRequest

	close   func()
	runOnce bool

	expectingInternalChannel atomic.Bool
	internalSession          atomic.Pointer[ChannelHandler]

	// Internal data models
	channelModel    *models.ChannelModel
	routeModel      *models.RouteModel
	permissionModel *models.PermissionModel
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
		terminateC:              make(chan error, 1),
		internalChannelRequestC: make(chan InternalChannelRequest, 1),
		handoffRequestC:         make(chan HandoffRequest, 1),
		close: func() {
			onClosed()
			close(writeC)
		},
		channelModel:    models.NewChannelModel(),
		routeModel:      models.NewRouteModel(cliCtrl.EventHandlers().RouteDataModelEventHandlers),
		permissionModel: models.NewPermissionModel(),
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
func (sh *StreamHandler) OnRoutesUpdated(routes []portforward.RouteInfo) {
	sh.routeModel.HandleRoutesUpdate(routes)
}

func (sh *StreamHandler) OnClusterHealthUpdate(_ context.Context, event *datav3.HealthCheckEvent) {
	sh.routeModel.HandleClusterHealthUpdate(event)
}

func (sh *StreamHandler) Terminate(err error) {
	sh.terminateC <- err
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
		return nil, context.Cause(ctx)
	case err := <-sh.terminateC:
		return nil, err
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
	state := &StreamState{
		RemainingUnauthenticatedMethods: []string{MethodPublicKey},
		StreamAuthInfo: StreamAuthInfo{
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
		case err := <-sh.terminateC:
			return err
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

	pendingUser := state.CurrentUser
	if err := pendingUser.PromoteFrom(req.User); err != nil {
		req.Err <- status.Error(codes.InvalidArgument, err.Error())
		return
	}
	err := sh.auth.EvaluateDelayed(ctx, state.StreamAuthInfo, req.User)
	if err != nil {
		lg.Debug().Err(err).Msg("ssh: handoff request denied")
		req.Err <- status.Error(codes.PermissionDenied, err.Error())
		return
	}
	state.CurrentUser = pendingUser
	lg.Debug().Msg("ssh: user updated successfully; initiating handoff to upstream")
	req.Reply <- buildHandoffAction(state, req.PtyInfo)
}

func (sh *StreamHandler) handleInternalChannelRequest(state *StreamState, c InternalChannelRequest) {
	if !sh.expectingInternalChannel.Load() {
		panic("bug: unexpected internal channel request")
	}
	state.DownstreamChannelInfo = c.DownstreamChannelInfo
	state.ChannelType = c.ChannelType
	c.Reply <- InternalChannelReply{
		StreamAuthInfo: state.StreamAuthInfo.Clone(),
		CurrentUser:    state.CurrentUser,
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
		reply.ChannelType = msg.ChanType
		if reply.CurrentUser.Hostname() != "" {
			panic("bug: current hostname is not empty")
		}
		currentUsername := reply.CurrentUser.Username()
		channel := NewChannelImpl(
			newStreamHandlerInterfaceImpl(sh, currentUsername, downstreamInfo.DownstreamChannelId, reply.StreamAuthInfo),
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
	if !slices.Contains(state.RemainingUnauthenticatedMethods, req.AuthMethod) {
		return status.Errorf(codes.InvalidArgument, "unexpected auth method: %s", req.AuthMethod)
	}

	if err := state.CurrentUser.SetOrCheckEqual(req.Username, req.Hostname); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	updateMethods := func(add []string) {
		state.RemainingUnauthenticatedMethods = slices.Remove(state.RemainingUnauthenticatedMethods, req.AuthMethod)
		state.RemainingUnauthenticatedMethods = append(state.RemainingUnauthenticatedMethods, add...)
	}
	log.Ctx(ctx).Debug().
		Str("method", req.AuthMethod).
		Str("username", state.CurrentUser.Username()).
		Str("hostname", state.CurrentUser.Hostname()).
		Msg("ssh: handling auth request")

	var partial bool
	switch req.AuthMethod {
	case MethodPublicKey:
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		pubkeyReq, ok := methodReq.(*extensions_ssh.PublicKeyMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid public key method request type")
		}
		response, err := sh.auth.HandlePublicKeyMethodRequest(ctx, state.StreamAuthInfo, state.CurrentUser, pubkeyReq)
		if err != nil {
			return err
		} else if response.Allow != nil {
			partial = true
			state.PublicKeyFingerprintSha256 = pubkeyReq.PublicKeyFingerprintSha256
		}
		state.PublicKeyAllow.Update(response.Allow)
		updateMethods(response.RequireAdditionalMethods)
	case MethodKeyboardInteractive:
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		kbiReq, ok := methodReq.(*extensions_ssh.KeyboardInteractiveMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid keyboard-interactive method request type")
		}
		response, err := sh.auth.HandleKeyboardInteractiveMethodRequest(ctx, state.StreamAuthInfo, state.CurrentUser, kbiReq, sh)
		if err != nil {
			return err
		}
		partial = response.Allow != nil
		state.KeyboardInteractiveAllow.Update(response.Allow)
		updateMethods(response.RequireAdditionalMethods)
	default:
		return status.Errorf(codes.Internal, "bug: server requested an unsupported auth method %q", req.AuthMethod)
	}
	log.Ctx(ctx).Debug().
		Str("method", req.AuthMethod).
		Bool("partial", partial).
		Strs("methods-remaining", state.RemainingUnauthenticatedMethods).
		Msg("ssh: auth request complete")

	if len(state.RemainingUnauthenticatedMethods) == 0 && state.allMethodsValid() {
		// If there are no methods remaining, the user is allowed if all attempted
		// methods have a valid response in the state
		state.InitialAuthComplete = true
		log.Ctx(ctx).Debug().Msg("ssh: all methods valid, sending allow response")
		sh.sendAllowResponse(state)
	} else {
		log.Ctx(ctx).Debug().Msg("ssh: unauthenticated methods remain, sending deny response")
		sh.sendDenyResponseWithRemainingMethods(partial, state)
	}
	return nil
}

func (sh *StreamHandler) reauth(ctx context.Context, state *StreamState) error {
	if !state.InitialAuthComplete {
		return nil
	}
	return sh.auth.EvaluateDelayed(ctx, state.StreamAuthInfo, state.CurrentUser)
}

func buildHandoffAction(state *StreamState, ptyInfo api.SSHPtyInfo) *extensions_ssh.SSHChannelControlAction {
	upstreamAllow := buildUpstreamAllowResponse(state.StreamAuthInfo, state.CurrentUser)
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
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Deny{
					Deny: &extensions_ssh.DenyResponse{
						Partial: partial,
						Methods: state.RemainingUnauthenticatedMethods,
					},
				},
			},
		},
	}
}

func (sh *StreamHandler) sendAllowResponse(state *StreamState) {
	var allow *extensions_ssh.AllowResponse
	if !state.CurrentUser.Valid() {
		panic("bug: current user invalid")
	}
	if state.CurrentUser.Hostname() == "" {
		sh.expectingInternalChannel.Store(true)
		allow = buildInternalAllowResponse(state.StreamAuthInfo, state.CurrentUser)
	} else {
		allow = buildUpstreamAllowResponse(state.StreamAuthInfo, state.CurrentUser)
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

func buildUpstreamAllowResponse(info StreamAuthInfo, user api.UserRequest) *extensions_ssh.AllowResponse {
	var allowedMethods []*extensions_ssh.AllowedMethod
	if value := info.PublicKeyAllow.Value; value != nil {
		allowedMethods = append(allowedMethods, &extensions_ssh.AllowedMethod{
			Method:     MethodPublicKey,
			MethodData: protoutil.NewAny(value),
		})
	}
	if value := info.KeyboardInteractiveAllow.Value; value != nil {
		allowedMethods = append(allowedMethods, &extensions_ssh.AllowedMethod{
			Method:     MethodKeyboardInteractive,
			MethodData: protoutil.NewAny(value),
		})
	}
	return &extensions_ssh.AllowResponse{
		Username: user.Username(),
		Target: &extensions_ssh.AllowResponse_Upstream{
			Upstream: &extensions_ssh.UpstreamTarget{
				Hostname:       user.Hostname(),
				DirectTcpip:    info.ChannelType == ChannelTypeDirectTcpip,
				AllowedMethods: allowedMethods,
			},
		},
	}
}

func buildInternalAllowResponse(info StreamAuthInfo, user api.UserRequest) *extensions_ssh.AllowResponse {
	return &extensions_ssh.AllowResponse{
		Username: user.Username(),
		Target: &extensions_ssh.AllowResponse_Internal{
			Internal: &extensions_ssh.InternalTarget{
				SetMetadata: &corev3.Metadata{
					TypedFilterMetadata: map[string]*anypb.Any{
						"com.pomerium.ssh": protoutil.NewAny(&extensions_ssh.FilterMetadata{
							StreamId: info.StreamID,
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
	authInfo            StreamAuthInfo
}

// Returns an api.StreamHandlerInterface given a StreamHandler along with extra
// fields contained in the StreamState which are needed to implement this
// interface. The StreamState is not stored in the StreamHandler, so it cannot
// implement this interface itself.
func newStreamHandlerInterfaceImpl(sh *StreamHandler, username string, downstreamChannelID uint32, authInfo StreamAuthInfo) api.StreamHandlerInterface {
	return &streamHandlerInterfaceImpl{
		StreamHandler:       sh,
		username:            username,
		downstreamChannelID: downstreamChannelID,
		authInfo:            authInfo,
	}
}

// DownstreamChannelID implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) DownstreamChannelID() uint32 {
	return si.downstreamChannelID
}

// DownstreamSourceAddress implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) DownstreamSourceAddress() string {
	return si.authInfo.SourceAddress
}

// DownstreamPublicKeyFingerprint implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) DownstreamPublicKeyFingerprint() []byte {
	return si.authInfo.PublicKeyFingerprintSha256
}

// Username implements StreamHandlerInterface.
func (si *streamHandlerInterfaceImpl) Username() string {
	return si.username
}

// GetSession implements StreamHandlerInterface
func (si *streamHandlerInterfaceImpl) GetSession(ctx context.Context) (*session.Session, error) {
	return si.auth.GetSession(ctx, si.authInfo)
}

// DeleteSession implements StreamHandlerInterface
func (si *streamHandlerInterfaceImpl) DeleteSession(ctx context.Context) error {
	return si.auth.DeleteSession(ctx, si.authInfo)
}
