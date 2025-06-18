package ssh

import (
	"context"
	"fmt"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/slices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
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
	StreamID                        uint64
	Username                        string
	Hostname                        string
	PublicKeyAllow                  *extensions_ssh.PublicKeyAllowResponse
	KeyboardInteractiveAllow        *extensions_ssh.KeyboardInteractiveAllowResponse
	RemainingUnauthenticatedMethods []string
}

// Handles a single SSH stream
type StreamHandler struct {
	Auth   AuthInterface
	WriteC chan<- *extensions_ssh.ServerMessage
	ReadC  <-chan *extensions_ssh.ClientMessage

	pendingInfoResponse chan chan *extensions_ssh.KeyboardInteractiveInfoPromptResponses
	state               *StreamState
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
	sh.WriteC <- &extensions_ssh.ServerMessage{
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
	errC := make(chan error, 1)
	for {
		select {
		case err := <-errC:
			return err
		case req, ok := <-sh.ReadC:
			if !ok {
				return nil
			}
			switch req := req.Message.(type) {
			case *extensions_ssh.ClientMessage_Event:
				switch event := req.Event.Event.(type) {
				case *extensions_ssh.StreamEvent_DownstreamConnected:
					id := event.DownstreamConnected.StreamId
					if id == 0 {
						return fmt.Errorf("invalid stream ID: %v", id)
					}
					sh.state.StreamID = id
					log.Ctx(ctx).Debug().Uint64("stream-id", id).Msg("ssh: downstream connected")
				case *extensions_ssh.StreamEvent_UpstreamConnected:
					log.Ctx(ctx).Debug().Uint64("stream-id", sh.state.StreamID).Msg("ssh: upstream connected")
				case *extensions_ssh.StreamEvent_DownstreamDisconnected:
					log.Ctx(ctx).Debug().Uint64("stream-id", sh.state.StreamID).Msg("ssh: downstream disconnected")
				case nil:
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

func (sh *StreamHandler) handleInfoResponse(ctx context.Context, resp *extensions_ssh.InfoResponse) error {
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
		resp, err := sh.Auth.AuthorizePublicKey(ctx, pubkeyReq)
		if err != nil {
			return err
		}
		if resp.Allow != nil {
			sh.state.PublicKeyAllow = resp.Allow
			sh.handleAuthMethodSuccess("publickey")
		} else if resp.Retry {
			sh.sendDenyWithCurrentMethods()
		}
		return nil
	case "keyboard-interactive":
		methodReq, _ := req.MethodRequest.UnmarshalNew()
		kbiReq, ok := methodReq.(*extensions_ssh.KeyboardInteractiveMethodRequest)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "invalid public key method request type")
		}
		resp, err := sh.Auth.AuthorizeKeyboardInteractive(ctx, kbiReq, sh)
		if err != nil {
			return err
		}
		if resp.Allow != nil {
			sh.state.KeyboardInteractiveAllow = resp.Allow
			sh.handleAuthMethodSuccess("publickey")
		} else if resp.Retry {
			sh.sendDenyWithCurrentMethods()
		}
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unsupported auth method: %s", req.AuthMethod)
	}
}

func (sh *StreamHandler) sendDenyWithCurrentMethods() {
	resp := extensions_ssh.ServerMessage{
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
	sh.WriteC <- &resp
}

func (sh *StreamHandler) sendPartialSuccess() {
	resp := extensions_ssh.ServerMessage{
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
	sh.WriteC <- &resp
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
	panic("unimplemented")
}
