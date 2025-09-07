package ssh

import (
	"context"
	"fmt"
	"iter"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/slices"
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

//go:generate go run go.uber.org/mock/mockgen -typed -destination ./mock/mock_auth_interface.go . AuthInterface

type AuthInterface interface {
	HandlePublicKeyMethodRequest(ctx context.Context, info StreamAuthInfo, req *extensions_ssh.PublicKeyMethodRequest) (PublicKeyAuthMethodResponse, error)
	HandleKeyboardInteractiveMethodRequest(ctx context.Context, info StreamAuthInfo, req *extensions_ssh.KeyboardInteractiveMethodRequest, querier KeyboardInteractiveQuerier) (KeyboardInteractiveAuthMethodResponse, error)
	EvaluateDelayed(ctx context.Context, info StreamAuthInfo) error
	FormatSession(ctx context.Context, info StreamAuthInfo) ([]byte, error)
	DeleteSession(ctx context.Context, info StreamAuthInfo) error
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
}

type AuthMethodValue[T any] struct {
	attempted bool
	Value     *T
}

func (v *AuthMethodValue[T]) Update(value *T) {
	v.attempted = true
	v.Value = value
}

func (v *AuthMethodValue[T]) IsValid() bool {
	if v.attempted {
		// method was attempted - valid iff there is a value
		return v.Value != nil
	}
	return true // method was not attempted - valid
}

type StreamAuthInfo struct {
	Username                   *string
	Hostname                   *string
	StreamID                   uint64
	SourceAddress              string
	ChannelType                string
	PublicKeyFingerprintSha256 []byte
	PublicKeyAllow             AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]
	KeyboardInteractiveAllow   AuthMethodValue[extensions_ssh.KeyboardInteractiveAllowResponse]
	InitialAuthComplete        bool
}

func (i *StreamAuthInfo) allMethodsValid() bool {
	return i.PublicKeyAllow.IsValid() && i.KeyboardInteractiveAllow.IsValid()
}

type StreamState struct {
	StreamAuthInfo
	RemainingUnauthenticatedMethods []string
	DownstreamChannelInfo           *extensions_ssh.SSHDownstreamChannelInfo
}

// StreamHandler handles a single SSH stream
type StreamHandler struct {
	auth       AuthInterface
	discovery  EndpointDiscoveryInterface
	config     *config.Config
	downstream *extensions_ssh.DownstreamConnectEvent
	writeC     chan *extensions_ssh.ServerMessage
	readC      chan *extensions_ssh.ClientMessage
	reauthC    chan struct{}
	terminateC chan error

	state *StreamState
	close func()

	expectingInternalChannel bool
	internalSession          atomic.Pointer[ChannelHandler]

	demoMode bool
}

var _ StreamHandlerInterface = (*StreamHandler)(nil)

func (sh *StreamHandler) Terminate(err error) {
	sh.terminateC <- err
}

func (sh *StreamHandler) Close() {
	sh.close()
}

func (sh *StreamHandler) IsExpectingInternalChannel() bool {
	return sh.expectingInternalChannel
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
	if sh.state != nil {
		panic("Run called twice")
	}
	sh.state = &StreamState{
		RemainingUnauthenticatedMethods: []string{MethodPublicKey},
		StreamAuthInfo: StreamAuthInfo{
			StreamID:      sh.downstream.StreamId,
			SourceAddress: sh.downstream.SourceAddress,
		},
	}
	cancelReauth := sh.periodicReauth()
	defer cancelReauth()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-sh.reauthC:
			if err := sh.reauth(ctx); err != nil {
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
					if ch := sh.internalSession.Load(); ch != nil {
						ch.HandleEvent(event.ChannelEvent)
					}
					// if there is no internal session, this is a no-op
				case *extensions_ssh.StreamEvent_GlobalRequest:
					if err := sh.handleGlobalRequest(event.GlobalRequest); err != nil {
						return err
					}
				case nil:
					return status.Errorf(codes.Internal, "received invalid event")
				}
			case *extensions_ssh.ClientMessage_AuthRequest:
				if err := sh.handleAuthRequest(ctx, req.AuthRequest); err != nil {
					return err
				}
			default:
				return status.Errorf(codes.Internal, "received invalid message")
			}
		}
	}
}

func (sh *StreamHandler) handleGlobalRequest(request *extensions_ssh.GlobalRequest) error {
	switch request := request.Request.(type) {
	case *extensions_ssh.GlobalRequest_TcpipForwardRequest_:
		host := request.TcpipForwardRequest.RemoteAddress

		// <- auth goes here

		// not the real logic
		routeID := ""
		for p := range sh.config.Options.GetAllPolicies() {
			if p.From == fmt.Sprintf("https://%s", host) {
				routeID = p.MustRouteID()
			}
		}
		if routeID == "" {
			return status.Errorf(codes.InvalidArgument, "no matching route")
		}

		sh.discovery.SetClusterEndpointForStream("route-" + routeID)
		// action := &extensions_ssh.SSHChannelControlAction{
		// 	Action: &extensions_ssh.SSHChannelControlAction_BeginUpstreamTunnel{
		// 		BeginUpstreamTunnel: &extensions_ssh.BeginUpstreamTunnel{
		// 			ClusterId: "route-" + routeID,
		// 		},
		// 	},
		// }
		// actionAny, _ := anypb.New(action)
		// stream.Send(&extensions_ssh.ChannelMessage{
		// 	Message: &extensions_ssh.ChannelMessage_ChannelControl{
		// 		ChannelControl: &extensions_ssh.ChannelControl{
		// 			Protocol:      "ssh",
		// 			ControlAction: actionAny,
		// 		},
		// 	},
		// })
		sh.demoMode = true
		return nil
	default:
		return status.Errorf(codes.Unimplemented, "received unknown global request")
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

	sh.state.DownstreamChannelInfo = &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               msg.ChanType,
		DownstreamChannelId:       msg.PeersID,
		InternalUpstreamChannelId: metadata.ChannelId,
		InitialWindowSize:         msg.PeersWindow,
		MaxPacketSize:             msg.MaxPacketSize,
	}
	sh.state.ChannelType = msg.ChanType
	channel := NewChannelImpl(sh, stream, sh.state.DownstreamChannelInfo)
	switch msg.ChanType {
	case ChannelTypeSession:
		ch := NewChannelHandler(channel, sh.config)
		if sh.internalSession.CompareAndSwap(nil, ch) {
			if err := channel.SendMessage(ChannelOpenConfirmMsg{
				PeersID:       sh.state.DownstreamChannelInfo.DownstreamChannelId,
				MyID:          sh.state.DownstreamChannelInfo.InternalUpstreamChannelId,
				MyWindow:      ChannelWindowSize,
				MaxPacketSize: ChannelMaxPacket,
			}); err != nil {
				return err
			}
			err := ch.Run(stream.Context(), sh.demoMode)
			sh.internalSession.Store(nil)
			return err
		} else {
			return channel.SendMessage(ChannelOpenFailureMsg{
				PeersID: sh.state.DownstreamChannelInfo.DownstreamChannelId,
				Reason:  Prohibited,
				Message: "multiple concurrent internal session channels not supported",
			})
		}
	case ChannelTypeDirectTcpip:
		if !sh.config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHAllowDirectTcpip) {
			return status.Errorf(codes.Unavailable, "direct-tcpip channels are not enabled")
		}
		var subMsg ChannelOpenDirectMsg
		if err := gossh.Unmarshal(msg.TypeSpecificData, &subMsg); err != nil {
			return err
		}
		action, err := sh.PrepareHandoff(stream.Context(), subMsg.DestAddr, nil)
		if err != nil {
			return err
		}
		return channel.SendControlAction(action)
	default:
		return status.Errorf(codes.InvalidArgument, "unexpected channel type in ChannelOpen message: %s", msg.ChanType)
	}
}

func (sh *StreamHandler) handleAuthRequest(ctx context.Context, req *extensions_ssh.AuthenticationRequest) error {
	if req.Protocol != "ssh" {
		return status.Errorf(codes.InvalidArgument, "invalid protocol: %s", req.Protocol)
	}
	if req.Service != ServiceConnection {
		return status.Errorf(codes.InvalidArgument, "invalid service: %s", req.Service)
	}
	if !slices.Contains(sh.state.RemainingUnauthenticatedMethods, req.AuthMethod) {
		return status.Errorf(codes.InvalidArgument, "unexpected auth method: %s", req.AuthMethod)
	}

	if sh.state.Username == nil {
		if req.Username == "" {
			return status.Errorf(codes.InvalidArgument, "username missing")
		}
		sh.state.Username = &req.Username
	} else if *sh.state.Username != req.Username {
		return status.Errorf(codes.InvalidArgument, "inconsistent username")
	}
	if sh.state.Hostname == nil {
		sh.state.Hostname = &req.Hostname
	} else if *sh.state.Hostname != req.Hostname {
		return status.Errorf(codes.InvalidArgument, "inconsistent hostname")
	}

	updateMethods := func(add []string) {
		sh.state.RemainingUnauthenticatedMethods = slices.Remove(sh.state.RemainingUnauthenticatedMethods, req.AuthMethod)
		sh.state.RemainingUnauthenticatedMethods = append(sh.state.RemainingUnauthenticatedMethods, add...)
	}
	log.Ctx(ctx).Debug().
		Str("method", req.AuthMethod).
		Str("username", *sh.state.Username).
		Str("hostname", *sh.state.Hostname).
		Msg("ssh: handling auth request")

	var partial bool
	switch req.AuthMethod {
	case MethodPublicKey:
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		pubkeyReq, ok := methodReq.(*extensions_ssh.PublicKeyMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid public key method request type")
		}
		response, err := sh.auth.HandlePublicKeyMethodRequest(ctx, sh.state.StreamAuthInfo, pubkeyReq)
		if err != nil {
			return err
		} else if response.Allow != nil {
			partial = true
			sh.state.PublicKeyFingerprintSha256 = pubkeyReq.PublicKeyFingerprintSha256
		}
		sh.state.PublicKeyAllow.Update(response.Allow)
		updateMethods(response.RequireAdditionalMethods)
	case MethodKeyboardInteractive:
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		kbiReq, ok := methodReq.(*extensions_ssh.KeyboardInteractiveMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid keyboard-interactive method request type")
		}
		response, err := sh.auth.HandleKeyboardInteractiveMethodRequest(ctx, sh.state.StreamAuthInfo, kbiReq, sh)
		if err != nil {
			return err
		}
		partial = response.Allow != nil
		sh.state.KeyboardInteractiveAllow.Update(response.Allow)
		updateMethods(response.RequireAdditionalMethods)
	default:
		return status.Errorf(codes.Internal, "bug: server requested an unsupported auth method %q", req.AuthMethod)
	}
	log.Ctx(ctx).Debug().
		Str("method", req.AuthMethod).
		Bool("partial", partial).
		Strs("methods-remaining", sh.state.RemainingUnauthenticatedMethods).
		Msg("ssh: auth request complete")

	if len(sh.state.RemainingUnauthenticatedMethods) == 0 && sh.state.allMethodsValid() {
		// if there are no methods remaining, the user is allowed if all attempted
		// methods have a valid response in the state
		sh.state.InitialAuthComplete = true
		log.Ctx(ctx).Debug().Msg("ssh: all methods valid, sending allow response")
		sh.sendAllowResponse()
	} else {
		log.Ctx(ctx).Debug().Msg("ssh: unauthenticated methods remain, sending deny response")
		sh.sendDenyResponseWithRemainingMethods(partial)
	}
	return nil
}

func (sh *StreamHandler) reauth(ctx context.Context) error {
	if !sh.state.InitialAuthComplete {
		return nil
	}
	return sh.auth.EvaluateDelayed(ctx, sh.state.StreamAuthInfo)
}

func (sh *StreamHandler) PrepareHandoff(ctx context.Context, hostname string, ptyInfo *extensions_ssh.SSHDownstreamPTYInfo) (*extensions_ssh.SSHChannelControlAction, error) {
	if hostname == "" {
		return nil, status.Errorf(codes.PermissionDenied, "invalid hostname")
	}
	if sh.state.Hostname == nil {
		panic("bug: PrepareHandoff called but state is missing a hostname")
	}
	if *sh.state.Hostname != "" {
		panic("bug: PrepareHandoff called but previous hostname is not empty")
	}
	*sh.state.Hostname = hostname
	err := sh.auth.EvaluateDelayed(ctx, sh.state.StreamAuthInfo)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	log.Ctx(ctx).Debug().
		Str("hostname", *sh.state.Hostname).
		Str("username", *sh.state.Username).
		Msg("ssh: initiating handoff to upstream")
	upstreamAllow := sh.buildUpstreamAllowResponse()
	action := &extensions_ssh.SSHChannelControlAction{
		Action: &extensions_ssh.SSHChannelControlAction_HandOff{
			HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
				DownstreamChannelInfo: sh.state.DownstreamChannelInfo,
				DownstreamPtyInfo:     ptyInfo,
				UpstreamAuth:          upstreamAllow,
			},
		},
	}
	return action, nil
}

func (sh *StreamHandler) FormatSession(ctx context.Context) ([]byte, error) {
	return sh.auth.FormatSession(ctx, sh.state.StreamAuthInfo)
}

func (sh *StreamHandler) DeleteSession(ctx context.Context) error {
	return sh.auth.DeleteSession(ctx, sh.state.StreamAuthInfo)
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

// DownstreamChannelID implements StreamHandlerInterface.
func (sh *StreamHandler) DownstreamChannelID() uint32 {
	return sh.state.DownstreamChannelInfo.DownstreamChannelId
}

// Hostname implements StreamHandlerInterface.
func (sh *StreamHandler) Hostname() *string {
	return sh.state.Hostname
}

// Username implements StreamHandlerInterface.
func (sh *StreamHandler) Username() *string {
	return sh.state.Username
}

func (sh *StreamHandler) sendDenyResponseWithRemainingMethods(partial bool) {
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Deny{
					Deny: &extensions_ssh.DenyResponse{
						Partial: partial,
						Methods: sh.state.RemainingUnauthenticatedMethods,
					},
				},
			},
		},
	}
}

func (sh *StreamHandler) sendAllowResponse() {
	var allow *extensions_ssh.AllowResponse
	if *sh.state.Hostname == "" {
		sh.expectingInternalChannel = true
		allow = sh.buildInternalAllowResponse()
	} else {
		allow = sh.buildUpstreamAllowResponse()
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

func (sh *StreamHandler) buildUpstreamAllowResponse() *extensions_ssh.AllowResponse {
	var allowedMethods []*extensions_ssh.AllowedMethod
	if value := sh.state.PublicKeyAllow.Value; value != nil {
		allowedMethods = append(allowedMethods, &extensions_ssh.AllowedMethod{
			Method:     MethodPublicKey,
			MethodData: protoutil.NewAny(value),
		})
	}
	if value := sh.state.KeyboardInteractiveAllow.Value; value != nil {
		allowedMethods = append(allowedMethods, &extensions_ssh.AllowedMethod{
			Method:     MethodKeyboardInteractive,
			MethodData: protoutil.NewAny(value),
		})
	}
	return &extensions_ssh.AllowResponse{
		Username: *sh.state.Username,
		Target: &extensions_ssh.AllowResponse_Upstream{
			Upstream: &extensions_ssh.UpstreamTarget{
				Hostname:       *sh.state.Hostname,
				DirectTcpip:    sh.state.ChannelType == ChannelTypeDirectTcpip,
				AllowedMethods: allowedMethods,
			},
		},
	}
}

func (sh *StreamHandler) buildInternalAllowResponse() *extensions_ssh.AllowResponse {
	return &extensions_ssh.AllowResponse{
		Username: *sh.state.Username,
		Target: &extensions_ssh.AllowResponse_Internal{
			Internal: &extensions_ssh.InternalTarget{
				SetMetadata: &corev3.Metadata{
					TypedFilterMetadata: map[string]*anypb.Any{
						"com.pomerium.ssh": protoutil.NewAny(&extensions_ssh.FilterMetadata{
							StreamId: sh.downstream.StreamId,
						}),
					},
				},
			},
		},
	}
}
