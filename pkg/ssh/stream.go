package ssh

import (
	"context"
	"iter"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/slices"
)

const (
	MethodPublicKey           = "publickey"
	MethodKeyboardInteractive = "keyboard-interactive"
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

type AuthInterface interface {
	HandlePublicKeyMethodRequest(ctx context.Context, info StreamAuthInfo, req *extensions_ssh.PublicKeyMethodRequest) (PublicKeyAuthMethodResponse, error)
	HandleKeyboardInteractiveMethodRequest(ctx context.Context, info StreamAuthInfo, req *extensions_ssh.KeyboardInteractiveMethodRequest, querier KeyboardInteractiveQuerier) (KeyboardInteractiveAuthMethodResponse, error)
	EvaluateDelayed(ctx context.Context, info StreamAuthInfo) error
	FormatSession(ctx context.Context, info StreamAuthInfo) ([]byte, error)
	DeleteSession(ctx context.Context, info StreamAuthInfo) error
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
	PublicKeyFingerprintSha256 []byte
	PublicKeyAllow             AuthMethodValue[extensions_ssh.PublicKeyAllowResponse]
	KeyboardInteractiveAllow   AuthMethodValue[extensions_ssh.KeyboardInteractiveAllowResponse]
}

func (i *StreamAuthInfo) allMethodsValid() bool {
	return i.PublicKeyAllow.IsValid() && i.KeyboardInteractiveAllow.IsValid()
}

type StreamState struct {
	StreamAuthInfo
	DirectTcpip                     bool
	RemainingUnauthenticatedMethods []string
	DownstreamChannelInfo           *extensions_ssh.SSHDownstreamChannelInfo
}

// StreamHandler handles a single SSH stream
type StreamHandler struct {
	auth       AuthInterface
	config     *config.Config
	downstream *extensions_ssh.DownstreamConnectEvent
	writeC     chan *extensions_ssh.ServerMessage
	readC      chan *extensions_ssh.ClientMessage

	state *StreamState
	close func()

	channelIDCounter         uint32
	expectingInternalChannel bool
}

var _ StreamHandlerInterface = (*StreamHandler)(nil)

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

// Prompt implements KeyboardInteractiveQuerier.
func (sh *StreamHandler) Prompt(ctx context.Context, prompts *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
	sh.sendInfoPrompts(prompts)
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case req := <-sh.readC:
		switch msg := req.Message.(type) {
		case *extensions_ssh.ClientMessage_InfoResponse:
			if msg.InfoResponse.Method != "keyboard-interactive" {
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
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case req := <-sh.readC:
			switch req := req.Message.(type) {
			case *extensions_ssh.ClientMessage_Event:
				switch event := req.Event.Event.(type) {
				case *extensions_ssh.StreamEvent_DownstreamConnected:
					// this was already received as the first message in the stream
					return status.Errorf(codes.Internal, "received duplicate downstream connected event")
				case *extensions_ssh.StreamEvent_UpstreamConnected:
					log.Ctx(ctx).Debug().
						Uint64("stream-id", event.UpstreamConnected.StreamId).
						Msg("ssh: upstream connected")
				case *extensions_ssh.StreamEvent_DownstreamDisconnected:
					log.Ctx(ctx).Debug().
						Uint64("stream-id", sh.downstream.StreamId).
						Str("reason", event.DownstreamDisconnected.Reason).
						Msg("ssh: downstream disconnected")
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

func (sh *StreamHandler) ServeChannel(stream extensions_ssh.StreamManagement_ServeChannelServer) error {
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

	sh.channelIDCounter++
	sh.state.DownstreamChannelInfo = &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               msg.ChanType,
		DownstreamChannelId:       msg.PeersID,
		InternalUpstreamChannelId: sh.channelIDCounter,
		InitialWindowSize:         msg.PeersWindow,
		MaxPacketSize:             msg.MaxPacketSize,
	}
	channel := NewChannelImpl(sh, stream, sh.state.DownstreamChannelInfo)
	switch msg.ChanType {
	case "session":
		if err := channel.SendMessage(ChannelOpenConfirmMsg{
			PeersID:       sh.state.DownstreamChannelInfo.DownstreamChannelId,
			MyID:          sh.state.DownstreamChannelInfo.InternalUpstreamChannelId,
			MyWindow:      ChannelWindowSize,
			MaxPacketSize: ChannelMaxPacket,
		}); err != nil {
			return err
		}
		ch := NewChannelHandler(channel, sh.config)
		return ch.Run(stream.Context())
	case "direct-tcpip":
		var subMsg ChannelOpenDirectMsg
		if err := gossh.Unmarshal(msg.TypeSpecificData, &subMsg); err != nil {
			return err
		}
		sh.state.DirectTcpip = true
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
	if req.Service != "ssh-connection" {
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
		}
		partial = response.Allow != nil
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
		log.Ctx(ctx).Debug().Msg("ssh: all methods valid, sending allow response")
		sh.sendAllowResponse()
	} else {
		log.Ctx(ctx).Debug().Msg("ssh: unauthenticated methods remain, sending deny response")
		sh.sendDenyResponseWithRemainingMethods(partial)
	}
	return nil
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
				DirectTcpip:    sh.state.DirectTcpip,
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
