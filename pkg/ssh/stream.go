package ssh

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/slices"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type KeyboardInteractiveQuerier interface {
	// Call this in a background goroutine. Prompts the client and returns their
	// responses to the given prompts.
	Prompt(ctx context.Context, prompts *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error)
}

type AuthMethodResult[AllowType any] struct {
	Allow *AllowType
	Retry bool
}

type (
	PublicKeyAuthMethodResult           = AuthMethodResult[extensions_ssh.PublicKeyAllowResponse]
	KeyboardInteractiveAuthMethodResult = AuthMethodResult[extensions_ssh.KeyboardInteractiveAllowResponse]
)

type AuthInterface interface {
	AuthorizePublicKey(ctx context.Context, req *extensions_ssh.PublicKeyMethodRequest) (PublicKeyAuthMethodResult, error)
	AuthorizeKeyboardInteractive(ctx context.Context, req *extensions_ssh.KeyboardInteractiveMethodRequest, querier KeyboardInteractiveQuerier) (KeyboardInteractiveAuthMethodResult, error)
}

type StreamState struct {
	Username                        string
	Hostname                        string
	PublicKeyAllow                  *extensions_ssh.PublicKeyAllowResponse
	KeyboardInteractiveAllow        *extensions_ssh.KeyboardInteractiveAllowResponse
	RemainingUnauthenticatedMethods []string
	DownstreamChannelInfo           *extensions_ssh.SSHDownstreamChannelInfo
}

// StreamHandler handles a single SSH stream
type StreamHandler struct {
	auth     AuthInterface
	streamID uint64
	writeC   chan *extensions_ssh.ServerMessage
	readC    chan *extensions_ssh.ClientMessage

	pendingInfoResponse chan chan *extensions_ssh.KeyboardInteractiveInfoPromptResponses
	state               *StreamState
	close               func()

	channelIDCounter         uint32
	expectingInternalChannel bool
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

// Prompt implements KeyboardInteractiveQuerier.
func (sh *StreamHandler) Prompt(ctx context.Context, prompts *extensions_ssh.KeyboardInteractiveInfoPrompts) (*extensions_ssh.KeyboardInteractiveInfoPromptResponses, error) {
	pendingResponseC := make(chan *extensions_ssh.KeyboardInteractiveInfoPromptResponses)
	select {
	case sh.pendingInfoResponse <- pendingResponseC:
	default:
		return nil, fmt.Errorf("")
	}

	infoReqAny, _ := anypb.New(prompts)
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_InfoRequest{
					InfoRequest: &extensions_ssh.InfoRequest{
						Method:  "keyboard-interactive",
						Request: infoReqAny,
					},
				},
			},
		},
	}

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case resp := <-pendingResponseC:
		return resp, nil
	}
}

func (sh *StreamHandler) Run(ctx context.Context) error {
	if sh.state != nil {
		panic("Run called twice")
	}
	sh.state = &StreamState{
		RemainingUnauthenticatedMethods: []string{"publickey", "keyboard-interactive"},
	}
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case req := <-sh.readC:
			switch req := req.Message.(type) {
			case *extensions_ssh.ClientMessage_Event:
				switch req.Event.Event.(type) {
				case *extensions_ssh.StreamEvent_DownstreamConnected:
					// this was already received as the first message in the stream
					return status.Errorf(codes.Internal, "received duplicate downstream connected event")
				case *extensions_ssh.StreamEvent_UpstreamConnected:
					log.Ctx(ctx).Debug().Uint64("stream-id", sh.streamID).Msg("ssh: upstream connected")
				case *extensions_ssh.StreamEvent_DownstreamDisconnected:
					log.Ctx(ctx).Debug().Uint64("stream-id", sh.streamID).Msg("ssh: downstream disconnected")
				case nil:
					return status.Errorf(codes.Internal, "received invalid event")
				}
			case *extensions_ssh.ClientMessage_AuthRequest:
				if err := sh.handleAuthRequest(ctx, req.AuthRequest); err != nil {
					return err
				}
			case *extensions_ssh.ClientMessage_InfoResponse:
				if err := sh.handleInfoResponse(ctx, req.InfoResponse); err != nil {
					return err
				}
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
	var msg channelOpenMsg
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

	remoteWindow := &Window{Cond: sync.NewCond(&sync.Mutex{})}
	remoteWindow.add(msg.PeersWindow)
	ch := NewChannelHandler(&channelImpl{
		handler:      sh,
		info:         sh.state.DownstreamChannelInfo,
		stream:       stream,
		remoteWindow: remoteWindow,
		localWindow:  ChannelWindowSize,
	})
	return ch.Run(stream.Context())
}

func (sh *StreamHandler) handleInfoResponse(_ context.Context, resp *extensions_ssh.InfoResponse) error {
	if resp.Method != "keyboard-interactive" {
		return status.Errorf(codes.InvalidArgument, "invalid method")
	}
	r, _ := resp.Response.UnmarshalNew()
	respInfo, ok := r.(*extensions_ssh.KeyboardInteractiveInfoPromptResponses)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid response type")
	}
	select {
	case pendingC := <-sh.pendingInfoResponse:
		pendingC <- respInfo
		return nil
	default:
		return status.Errorf(codes.FailedPrecondition, "no pending info request")
	}
}

func (sh *StreamHandler) handleAuthRequest(ctx context.Context, req *extensions_ssh.AuthenticationRequest) error {
	if req.Protocol != "ssh" {
		return status.Errorf(codes.InvalidArgument, "invalid protocol: %s", req.Protocol)
	}
	if req.Service != "ssh-connection" {
		return status.Errorf(codes.InvalidArgument, "invalid service: %s", req.Service)
	}
	if sh.state.Username == "" {
		if req.Username != "" {
			return status.Errorf(codes.InvalidArgument, "username missing")
		}
		sh.state.Username = req.Username
	} else if sh.state.Username != req.Username {
		return status.Errorf(codes.InvalidArgument, "inconsistent username")
	}
	if sh.state.Hostname == "" {
		if req.Hostname != "" {
			return status.Errorf(codes.InvalidArgument, "hostname missing")
		}
		sh.state.Hostname = req.Hostname
	} else if sh.state.Hostname != req.Hostname {
		return status.Errorf(codes.InvalidArgument, "inconsistent hostname")
	}

	switch req.AuthMethod {
	case "publickey":
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		pubkeyReq, ok := methodReq.(*extensions_ssh.PublicKeyMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid public key method request type")
		}
		resp, err := sh.auth.AuthorizePublicKey(ctx, pubkeyReq)
		if err != nil {
			return err
		}
		if resp.Allow != nil {
			sh.state.PublicKeyAllow = resp.Allow
			sh.handleAuthMethodSuccess(req.AuthMethod)
		} else if resp.Retry {
			sh.sendFailRetry()
		}
		return nil
	case "keyboard-interactive":
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		kbiReq, ok := methodReq.(*extensions_ssh.KeyboardInteractiveMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid public key method request type")
		}
		resp, err := sh.auth.AuthorizeKeyboardInteractive(ctx, kbiReq, sh)
		if err != nil {
			return err
		}
		if resp.Allow != nil {
			sh.state.KeyboardInteractiveAllow = resp.Allow
			sh.handleAuthMethodSuccess(req.AuthMethod)
		} else if resp.Retry {
			sh.sendFailRetry()
		}
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unsupported auth method: %s", req.AuthMethod)
	}
}

func (sh *StreamHandler) sendFailRetry() {
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Deny{
					Deny: &extensions_ssh.DenyResponse{
						Methods: sh.state.RemainingUnauthenticatedMethods,
					},
				},
			},
		},
	}
}

func (sh *StreamHandler) sendPartialSuccess() {
	sh.writeC <- &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Deny{
					Deny: &extensions_ssh.DenyResponse{
						Partial: true,
						Methods: sh.state.RemainingUnauthenticatedMethods,
					},
				},
			},
		},
	}
}

func (sh *StreamHandler) handleAuthMethodSuccess(method string) {
	sh.state.RemainingUnauthenticatedMethods = slices.Remove(sh.state.RemainingUnauthenticatedMethods, method)
	if len(sh.state.RemainingUnauthenticatedMethods) > 0 {
		sh.sendPartialSuccess()
	} else {
		sh.sendSuccess()
	}
}

func (sh *StreamHandler) sendSuccess() {
	var allow *extensions_ssh.AllowResponse
	if sh.state.Hostname == "" {
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

func (sh *StreamHandler) buildUpstreamAllowResponse() *extensions_ssh.AllowResponse {
	return &extensions_ssh.AllowResponse{
		Username: sh.state.Username,
		Target: &extensions_ssh.AllowResponse_Upstream{
			Upstream: &extensions_ssh.UpstreamTarget{
				Hostname: sh.state.Hostname,
				AllowedMethods: []*extensions_ssh.AllowedMethod{
					{
						Method:     "publickey",
						MethodData: marshalAny(sh.state.PublicKeyAllow),
					},
					{
						Method:     "keyboard-interactive",
						MethodData: marshalAny(sh.state.KeyboardInteractiveAllow),
					},
				},
			},
		},
	}
}

func (sh *StreamHandler) buildInternalAllowResponse() *extensions_ssh.AllowResponse {
	return &extensions_ssh.AllowResponse{
		Username: sh.state.Username,
		Target: &extensions_ssh.AllowResponse_Internal{
			Internal: &extensions_ssh.InternalTarget{
				SetMetadata: &corev3.Metadata{
					FilterMetadata: map[string]*structpb.Struct{
						"pomerium": {
							Fields: map[string]*structpb.Value{
								"stream-id": structpb.NewStringValue(strconv.FormatUint(sh.streamID, 10)),
							},
						},
					},
				},
			},
		},
	}
}

func marshalAny(msg proto.Message) *anypb.Any {
	a, err := anypb.New(msg)
	if err != nil {
		panic(err)
	}
	return a
}
