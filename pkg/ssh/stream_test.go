package ssh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/suite"
	. "go.uber.org/mock/gomock" //nolint
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/ssh"
	mock_ssh "github.com/pomerium/pomerium/pkg/ssh/mock"
)

var DefaultTimeout = 10 * time.Second

func init() {
	if isDebuggerAttached() {
		DefaultTimeout = 1 * time.Hour
	}
}

func isDebuggerAttached() bool {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/self/status")
		if err == nil {
			for line := range bytes.Lines(data) {
				if bytes.HasPrefix(line, []byte("TracerPid:\t")) {
					return line[11] != '0'
				}
			}
		}
	}
	return false
}

func HookWithArgs(f func(s *StreamHandlerSuite, args []any) any, args ...any) []func(s *StreamHandlerSuite) any {
	return []func(s *StreamHandlerSuite) any{
		func(s *StreamHandlerSuite) any {
			return f(s, args)
		},
	}
}

func RuntimeFlagDependentHookWithArgs(f func(s *StreamHandlerSuite, args []any) any, flag config.RuntimeFlag, argsIfEnabled []any, argsIfDisabled []any) []func(s *StreamHandlerSuite) any {
	return []func(s *StreamHandlerSuite) any{
		func(s *StreamHandlerSuite) any {
			if s.cfg.Options.IsRuntimeFlagSet(flag) {
				return f(s, argsIfEnabled)
			}
			return f(s, argsIfDisabled)
		},
	}
}

var (
	StreamHandlerSuiteBeforeTestHooks = map[string][]func(s *StreamHandlerSuite) any{}
	StreamHandlerSuiteAfterTestHooks  = map[string][]func(s *StreamHandlerSuite) any{}
)

type StreamHandlerSuiteOptions struct {
	ConfigModifiers []func(*config.Config)
}

type StreamHandlerSuite struct {
	suite.Suite
	StreamHandlerSuiteOptions

	ctrl *Controller

	mgr *ssh.StreamManager
	cfg *config.Config

	cleanup []func()
	errC    chan error

	mockAuth *mock_ssh.MockAuthInterface

	ed25519PublicKey     ed25519.PublicKey
	ed25519PrivateKey    ed25519.PrivateKey
	ed25519SshPublicKey  gossh.PublicKey
	ed25519SshPrivateKey gossh.Signer

	BeforeTestHookResult any
}

func (s *StreamHandlerSuite) SetupTest() {
	s.ctrl = NewController(s.T())
	s.mockAuth = mock_ssh.NewMockAuthInterface(s.ctrl)
	s.cleanup = []func(){}
	s.errC = make(chan error, 1)

	var err error
	s.ed25519PublicKey, s.ed25519PrivateKey, err = ed25519.GenerateKey(rand.Reader)
	s.Require().NoError(err)
	s.ed25519SshPublicKey, err = gossh.NewPublicKey(s.ed25519PublicKey)
	s.Require().NoError(err)
	s.ed25519SshPrivateKey, err = gossh.NewSignerFromKey(s.ed25519PrivateKey)
	s.Require().NoError(err)

	s.cfg = &config.Config{Options: config.NewDefaultOptions()}
	s.cfg.Options.Policies = []config.Policy{
		{From: "https://from.notssh.example.com", To: mustParseWeightedURLs(s.T(), "https://to.notssh.example.com")},
		{From: "ssh://host1", To: mustParseWeightedURLs(s.T(), "ssh://dest1:22")},
		{From: "https://from1.notssh.example.com", To: mustParseWeightedURLs(s.T(), "https://to1.notssh.example.com")},
		{From: "ssh://host2", To: mustParseWeightedURLs(s.T(), "ssh://dest2:22")},
		{From: "https://from2.notssh.example.com", To: mustParseWeightedURLs(s.T(), "https://to2.notssh.example.com")},
	}
	for _, f := range s.ConfigModifiers {
		f(s.cfg)
	}

	s.mgr = ssh.NewStreamManager(s.T().Context(), s.mockAuth, s.cfg)
	// intentionally don't call m.Run() - simulate initial sync completing
	s.mgr.ClearRecords(context.Background())
}

func (s *StreamHandlerSuite) TearDownTest() {
	for _, f := range s.cleanup {
		f()
	}
	s.ctrl.Finish()
}

func (s *StreamHandlerSuite) BeforeTest(_, testName string) {
	s.BeforeTestHookResult = nil
	for _, fn := range StreamHandlerSuiteBeforeTestHooks[testName] {
		s.BeforeTestHookResult = fn(s)
	}
}

//
// Helper methods
//

func marshalAny(msg proto.Message) *anypb.Any {
	a, err := anypb.New(msg)
	if err != nil {
		panic(err)
	}
	return a
}

func (s *StreamHandlerSuite) expectError(fn func(), msg string) {
	fn()
	select {
	case err := <-s.errC:
		s.ErrorContains(err, msg)
	case <-time.After(DefaultTimeout):
		s.FailNow(fmt.Sprintf("timed out waiting for error %q", msg))
	}
}

func (s *StreamHandlerSuite) startStreamHandler(streamID uint64) *ssh.StreamHandler {
	sh := s.mgr.NewStreamHandler(s.T().Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: streamID})
	s.errC = make(chan error, 1)
	ctx, ca := context.WithCancel(s.T().Context())
	go func() {
		defer close(s.errC)
		s.errC <- sh.Run(ctx)
	}()
	s.cleanup = append(s.cleanup, func() {
		start := time.Now()
		for len(sh.ReadC()) > 0 && time.Since(start) < 100*time.Millisecond {
			runtime.Gosched()
		}
		if len(sh.ReadC()) > 0 {
			s.Fail(fmt.Sprintf("read channel contains %d unhandled client messages", len(sh.ReadC())))
		}
		ca()
		var err error
		select {
		case err = <-s.errC:
		case <-time.After(DefaultTimeout):
			s.Fail("timed out waiting for stream handler to close")
		}

		sh.Close()
		if err != nil {
			s.Require().ErrorIs(err, context.Canceled)
		}
		if len(sh.WriteC()) != 0 {
			logs := []string{"write channel contains unhandled server messages:"}
			i := 0
			for msg := range sh.WriteC() {
				logs = append(logs, fmt.Sprintf("[%d]: %s", i, msg.String()))
				i++
			}
			s.Fail(strings.Join(logs, "\n"))
		}
	})
	return sh
}

func (s *StreamHandlerSuite) msgDownstreamConnected(streamID uint64) *extensions_ssh.ClientMessage {
	return &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_Event{
			Event: &extensions_ssh.StreamEvent{
				Event: &extensions_ssh.StreamEvent_DownstreamConnected{
					DownstreamConnected: &extensions_ssh.DownstreamConnectEvent{
						StreamId: streamID,
					},
				},
			},
		},
	}
}

func (s *StreamHandlerSuite) msgDownstreamDisconnected(reason string) *extensions_ssh.ClientMessage {
	return &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_Event{
			Event: &extensions_ssh.StreamEvent{
				Event: &extensions_ssh.StreamEvent_DownstreamDisconnected{
					DownstreamDisconnected: &extensions_ssh.DownstreamDisconnectedEvent{
						Reason: reason,
					},
				},
			},
		},
	}
}

func (s *StreamHandlerSuite) msgUpstreamConnected() *extensions_ssh.ClientMessage {
	return &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_Event{
			Event: &extensions_ssh.StreamEvent{
				Event: &extensions_ssh.StreamEvent_UpstreamConnected{
					UpstreamConnected: &extensions_ssh.UpstreamConnectEvent{},
				},
			},
		},
	}
}

func (s *StreamHandlerSuite) expectAllowUpstream(sh *ssh.StreamHandler, hostname string) {
	select {
	case msg := <-sh.WriteC():
		if authResp := msg.GetAuthResponse(); authResp != nil {
			if allow := authResp.GetAllow(); allow != nil {
				s.Require().NotNil(allow.GetUpstream(), "received an allow response, but not to an upstream target")
				s.Require().Equal(hostname, allow.GetUpstream().GetHostname())
			} else {
				s.FailNowf("received an auth response, but it was not an allow response", authResp.String())
			}
		} else {
			s.FailNow("received a message, but it was not an auth response", msg.String())
		}
	case <-time.After(DefaultTimeout):
		s.FailNow("timed out waiting for upstream allow message")
	}
}

func (s *StreamHandlerSuite) expectDeny(sh *ssh.StreamHandler, partial bool, methods []string) {
	select {
	case msg := <-sh.WriteC():
		if authResp := msg.GetAuthResponse(); authResp != nil {
			if deny := authResp.GetDeny(); deny != nil {
				s.Require().Equal(partial, deny.Partial)
				s.Require().Equal(methods, deny.Methods)
			} else {
				s.Require().Fail("received an auth response, but it was not a deny response", authResp.String())
			}
		} else {
			s.FailNow("received a message, but it was not an auth response", msg.String())
		}
	case <-time.After(DefaultTimeout):
		s.FailNow("timed out waiting for deny message")
	}
}

func (s *StreamHandlerSuite) expectAllowInternal(sh *ssh.StreamHandler) {
	select {
	case msg := <-sh.WriteC():
		if authResp := msg.GetAuthResponse(); authResp != nil {
			if allow := authResp.GetAllow(); allow != nil {
				s.Require().NotNil(allow.GetInternal(), "received an allow response, but not to an internal target")
			} else {
				s.FailNow("received an auth response, but it was not an allow response", authResp.String())
			}
		} else {
			s.FailNow("received a message, but it was not an auth response", msg.String())
		}
	case <-time.After(DefaultTimeout):
		s.FailNow("timed out waiting for internal allow message")
	}
}

func (s *StreamHandlerSuite) expectPrompt(sh *ssh.StreamHandler) {
	select {
	case msg := <-sh.WriteC():
		if authResp := msg.GetAuthResponse(); authResp != nil {
			if info := authResp.GetInfoRequest(); info != nil {
				s.Require().NotNil(info.GetRequest(), "received a nil info request")
			} else {
				s.FailNow("received an auth response, but it was not an info request", authResp.String())
			}
		} else {
			s.FailNow("received a message, but it was not an auth response", msg.String())
		}
	case <-time.After(DefaultTimeout):
		s.FailNow("timed out waiting for prompt message")
	}
}

func (s *StreamHandlerSuite) validPublicKeyMethodRequest() *anypb.Any {
	return marshalAny(&extensions_ssh.PublicKeyMethodRequest{
		PublicKey:                  s.ed25519SshPublicKey.Marshal(),
		PublicKeyAlg:               s.ed25519SshPublicKey.Type(),
		PublicKeyFingerprintSha256: []byte(gossh.FingerprintSHA256(s.ed25519SshPublicKey)),
	})
}

//
// Tests
//

func (s *StreamHandlerSuite) TestDuplicateDownstreamConnectedEvent() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- s.msgDownstreamConnected(1)
	}, "received duplicate downstream connected event")
}

func (s *StreamHandlerSuite) TestDownstreamDisconnectedEvent() {
	sh := s.startStreamHandler(1)
	sh.ReadC() <- s.msgDownstreamDisconnected("") // this just logs a message
}

func (s *StreamHandlerSuite) TestUpstreamConnectedEvent() {
	sh := s.startStreamHandler(1)
	sh.ReadC() <- s.msgUpstreamConnected() // this just logs a message
}

func (s *StreamHandlerSuite) TestInvalidEvent() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_Event{
				Event: &extensions_ssh.StreamEvent{Event: nil},
			},
		}
	}, "received invalid event")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_InvalidProtocol() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol: "not-ssh",
					Service:  "ssh-connection",
				},
			},
		}
	}, "invalid protocol: not-ssh")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_InvalidService() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol: "ssh",
					Service:  "ssh-userauth",
				},
			},
		}
	}, "invalid service: ssh-userauth")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_InvalidMessage() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: nil,
		}
	}, "received invalid client message type <nil>")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_FirstRequestIsKeyboardInteractive() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		// first request should be publickey
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:   "ssh",
					Service:    "ssh-connection",
					AuthMethod: "keyboard-interactive",
				},
			},
		}
	}, "unexpected auth method: keyboard-interactive")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_MissingUsername() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:   "ssh",
					Service:    "ssh-connection",
					AuthMethod: "publickey",
					Username:   "",
				},
			},
		}
	}, "username missing")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_EmptyHostname() {
	sh := s.startStreamHandler(1)

	// empty hostname is allowed initially
	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Return(ssh.PublicKeyAuthMethodResponse{Allow: &extensions_ssh.PublicKeyAllowResponse{
			PublicKey:   s.ed25519SshPublicKey.Marshal(),
			Permissions: &extensions_ssh.Permissions{},
		}}, nil)

	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}

	s.expectAllowInternal(sh)
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_MismatchedAuthMethodAndRequestType() {
	sh := s.startStreamHandler(1)

	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "publickey",
					Username:      "test",
					Hostname:      "",
					MethodRequest: marshalAny(&extensions_ssh.KeyboardInteractiveMethodRequest{}),
				},
			},
		}
	}, "invalid public key method request type")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_ValidPublicKeyMethodRequest() {
	sh := s.startStreamHandler(1)

	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Return(ssh.PublicKeyAuthMethodResponse{Allow: &extensions_ssh.PublicKeyAllowResponse{
			PublicKey:   s.ed25519SshPublicKey.Marshal(),
			Permissions: &extensions_ssh.Permissions{},
		}}, nil)

	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "host1",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}

	s.expectAllowUpstream(sh, "host1")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_ValidPublicKeyMethodRequestError() {
	sh := s.startStreamHandler(1)

	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Return(ssh.PublicKeyAuthMethodResponse{}, errors.New("test error"))

	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "publickey",
					Username:      "test",
					Hostname:      "host1",
					MethodRequest: s.validPublicKeyMethodRequest(),
				},
			},
		}
	}, "test error")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_PublicKeyRetry() {
	sh := s.startStreamHandler(1)

	i := -1
	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		MaxTimes(4).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, _ *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			i++
			switch i {
			case 0, 1, 2:
				return ssh.PublicKeyAuthMethodResponse{
					RequireAdditionalMethods: []string{"publickey"},
				}, nil
			case 3:
				return ssh.PublicKeyAuthMethodResponse{Allow: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey:   s.ed25519SshPublicKey.Marshal(),
					Permissions: &extensions_ssh.Permissions{},
				}}, nil
			default:
				panic("unreachable")
			}
		})

	for i := range 4 {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "publickey",
					Username:      "test",
					Hostname:      "host1",
					MethodRequest: s.validPublicKeyMethodRequest(),
				},
			},
		}
		if i < 3 {
			s.expectDeny(sh, false, []string{"publickey"})
		} else {
			s.expectAllowUpstream(sh, "host1")
		}
	}
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_InconsistentUsername() {
	sh := s.startStreamHandler(1)

	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Times(1).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, _ *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				RequireAdditionalMethods: []string{"publickey"},
			}, nil
		})
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "host1",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}
	s.expectDeny(sh, false, []string{"publickey"})
	s.Equal("test", *sh.Username())
	s.Equal("host1", *sh.Hostname())
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "publickey",
					Username:      "test2",
					Hostname:      "host1",
					MethodRequest: s.validPublicKeyMethodRequest(),
				},
			},
		}
	}, "inconsistent username")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_InconsistentHostname() {
	sh := s.startStreamHandler(1)

	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Times(1).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, _ *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				RequireAdditionalMethods: []string{"publickey"},
			}, nil
		})
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "host1",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}
	s.expectDeny(sh, false, []string{"publickey"})
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "publickey",
					Username:      "test",
					Hostname:      "host2",
					MethodRequest: s.validPublicKeyMethodRequest(),
				},
			},
		}
	}, "inconsistent hostname")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_InconsistentEmptyHostname() {
	sh := s.startStreamHandler(1)

	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Times(1).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, req *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				Allow: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey:   req.PublicKey,
					Permissions: &extensions_ssh.Permissions{},
				},
				RequireAdditionalMethods: []string{"keyboard-interactive"},
			}, nil
		})
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}
	s.expectDeny(sh, true, []string{"keyboard-interactive"})
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "keyboard-interactive",
					Username:      "test",
					Hostname:      "host1",
					MethodRequest: marshalAny(&extensions_ssh.KeyboardInteractiveMethodRequest{}),
				},
			},
		}
	}, "inconsistent hostname")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_UnknownAuthMethod() {
	sh := s.startStreamHandler(1)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:   "ssh",
					Service:    "ssh-connection",
					AuthMethod: "password",
					Username:   "test",
					Hostname:   "host1",
				},
			},
		}
	}, "unexpected auth method: password")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_UnimplementedAuthMethod() {
	sh := s.startStreamHandler(1)
	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Times(1).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, _ *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				RequireAdditionalMethods: []string{"password"},
			}, nil
		})
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "host1",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}
	s.expectDeny(sh, false, []string{"password"})
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:   "ssh",
					Service:    "ssh-connection",
					AuthMethod: "password",
					Username:   "test",
					Hostname:   "host1",
				},
			},
		}
	}, "bug: server requested an unsupported auth method \"password\"")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_WrongClientMessage() {
	sh := s.startStreamHandler(1)
	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Times(1).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, req *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				Allow: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey:   req.PublicKey,
					Permissions: &extensions_ssh.Permissions{},
				},
				RequireAdditionalMethods: []string{"keyboard-interactive"},
			}, nil
		})
	newMsg := func() *extensions_ssh.ClientMessage_AuthRequest {
		return &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "host1",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		}
	}
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: newMsg(),
	}
	s.expectDeny(sh, true, []string{"keyboard-interactive"})
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: newMsg(),
		}
	}, "unexpected auth method: publickey")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_KeyboardInteractive_WrongMethodRequestType() {
	sh := s.startStreamHandler(1)

	s.mockAuth.EXPECT().
		HandlePublicKeyMethodRequest(Any(), Any(), Any()).
		Times(1).
		DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, req *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				Allow: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey:   req.PublicKey,
					Permissions: &extensions_ssh.Permissions{},
				},
				RequireAdditionalMethods: []string{"keyboard-interactive"},
			}, nil
		})
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:      "ssh",
				Service:       "ssh-connection",
				AuthMethod:    "publickey",
				Username:      "test",
				Hostname:      "host1",
				MethodRequest: s.validPublicKeyMethodRequest(),
			},
		},
	}
	s.expectDeny(sh, true, []string{"keyboard-interactive"})
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "keyboard-interactive",
					Username:      "test",
					Hostname:      "host1",
					MethodRequest: s.validPublicKeyMethodRequest(),
				},
			},
		}
	}, "invalid keyboard-interactive method request type")
}

func init() {
	setupKeyboardInteractive := func(s *StreamHandlerSuite, input []any) any {
		querierErr, _ := input[0].(error)
		sh := s.startStreamHandler(100)

		i := -1
		s.mockAuth.EXPECT().
			HandlePublicKeyMethodRequest(Any(), Any(), Any()).
			Times(2).
			DoAndReturn(func(_ context.Context, _ ssh.StreamAuthInfo, _ *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
				i++
				switch i {
				case 0:
					return ssh.PublicKeyAuthMethodResponse{
						RequireAdditionalMethods: []string{"publickey"},
					}, nil
				case 1:
					return ssh.PublicKeyAuthMethodResponse{
						Allow: &extensions_ssh.PublicKeyAllowResponse{
							PublicKey:   s.ed25519SshPublicKey.Marshal(),
							Permissions: &extensions_ssh.Permissions{},
						},
						RequireAdditionalMethods: []string{"keyboard-interactive"},
					}, nil
				default:
					panic("unreachable")
				}
			})
		s.mockAuth.EXPECT().
			HandleKeyboardInteractiveMethodRequest(Any(), Any(), Any(), Any()).
			DoAndReturn(func(
				ctx context.Context,
				info ssh.StreamAuthInfo,
				_ *extensions_ssh.KeyboardInteractiveMethodRequest,
				querier ssh.KeyboardInteractiveQuerier,
			) (ssh.KeyboardInteractiveAuthMethodResponse, error) {
				s.Equal("test", *info.Username)
				s.Equal("host1", *info.Hostname)
				s.Equal(uint64(100), info.StreamID)
				resp, err := querier.Prompt(ctx, &extensions_ssh.KeyboardInteractiveInfoPrompts{
					Name:        "test-name",
					Instruction: "test-instruction",
					Prompts: []*extensions_ssh.KeyboardInteractiveInfoPrompts_Prompt{
						{
							Prompt: "test-prompt",
							Echo:   true,
						},
					},
				})
				s.Require().Equal(querierErr, err, "unexpected error from querier.Prompt")
				if querierErr == nil {
					s.Equal([]string{"test-prompt-response"}, resp.Responses)
					return ssh.KeyboardInteractiveAuthMethodResponse{
						Allow: &extensions_ssh.KeyboardInteractiveAllowResponse{},
					}, nil
				}
				return ssh.KeyboardInteractiveAuthMethodResponse{}, err
			})
		for range 2 {
			sh.ReadC() <- &extensions_ssh.ClientMessage{
				Message: &extensions_ssh.ClientMessage_AuthRequest{
					AuthRequest: &extensions_ssh.AuthenticationRequest{
						Protocol:      "ssh",
						Service:       "ssh-connection",
						AuthMethod:    "publickey",
						Username:      "test",
						Hostname:      "host1",
						MethodRequest: s.validPublicKeyMethodRequest(),
					},
				},
			}
		}
		s.expectDeny(sh, false, []string{"publickey"})
		s.expectDeny(sh, true, []string{"keyboard-interactive"})
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "keyboard-interactive",
					Username:      "test",
					Hostname:      "host1",
					MethodRequest: marshalAny(&extensions_ssh.KeyboardInteractiveMethodRequest{}),
				},
			},
		}

		return sh
	}
	StreamHandlerSuiteBeforeTestHooks["TestHandleAuthRequest_KeyboardInteractive"] = HookWithArgs(setupKeyboardInteractive, (error)(nil))
	StreamHandlerSuiteBeforeTestHooks["TestHandleAuthRequest_KeyboardInteractive_NoPromptReply"] = HookWithArgs(setupKeyboardInteractive, context.Canceled)
	StreamHandlerSuiteBeforeTestHooks["TestHandleAuthRequest_KeyboardInteractive_InvalidInfoResponse"] = HookWithArgs(setupKeyboardInteractive, status.Errorf(codes.Internal, "received invalid info response"))
	StreamHandlerSuiteBeforeTestHooks["TestHandleAuthRequest_KeyboardInteractive_InvalidPromptResponse"] = HookWithArgs(setupKeyboardInteractive, status.Errorf(codes.InvalidArgument, "received invalid prompt response"))
	StreamHandlerSuiteBeforeTestHooks["TestHandleAuthRequest_KeyboardInteractive_WrongResponseMessageType"] = HookWithArgs(setupKeyboardInteractive, status.Errorf(codes.InvalidArgument, "received invalid message, expecting info response"))
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_KeyboardInteractive() {
	sh := s.BeforeTestHookResult.(*ssh.StreamHandler)

	s.expectPrompt(sh)
	sh.ReadC() <- &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_InfoResponse{
			InfoResponse: &extensions_ssh.InfoResponse{
				Method: "keyboard-interactive",
				Response: marshalAny(&extensions_ssh.KeyboardInteractiveInfoPromptResponses{
					Responses: []string{"test-prompt-response"},
				}),
			},
		},
	}
	s.expectAllowUpstream(sh, "host1")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_KeyboardInteractive_NoPromptReply() {
	sh := s.BeforeTestHookResult.(*ssh.StreamHandler)
	s.expectPrompt(sh)
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_KeyboardInteractive_InvalidInfoResponse() {
	sh := s.BeforeTestHookResult.(*ssh.StreamHandler)
	s.expectPrompt(sh)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_InfoResponse{
				InfoResponse: &extensions_ssh.InfoResponse{
					Method: "publickey",
					Response: marshalAny(&extensions_ssh.KeyboardInteractiveInfoPromptResponses{
						Responses: []string{"test-prompt-response"},
					}),
				},
			},
		}
	}, "received invalid info response")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_KeyboardInteractive_InvalidPromptResponse() {
	sh := s.BeforeTestHookResult.(*ssh.StreamHandler)
	s.expectPrompt(sh)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_InfoResponse{
				InfoResponse: &extensions_ssh.InfoResponse{
					Method:   "keyboard-interactive",
					Response: nil,
				},
			},
		}
	}, "received invalid prompt response")
}

func (s *StreamHandlerSuite) TestHandleAuthRequest_KeyboardInteractive_WrongResponseMessageType() {
	sh := s.BeforeTestHookResult.(*ssh.StreamHandler)
	s.expectPrompt(sh)
	s.expectError(func() {
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "keyboard-interactive",
					Username:      "test",
					Hostname:      "host1",
					MethodRequest: marshalAny(&extensions_ssh.KeyboardInteractiveMethodRequest{}),
				},
			},
		}
	}, "received invalid message, expecting info response")
}

type mockGrpcServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *mockGrpcServerStream) Context() context.Context {
	return s.ctx
}

type mockChannelStream struct {
	*grpc.GenericServerStream[extensions_ssh.ChannelMessage, extensions_ssh.ChannelMessage]

	closeServerToClientOnce sync.Once
	serverToClient          chan *extensions_ssh.ChannelMessage
	closeClientToServerOnce sync.Once
	clientToServer          chan *extensions_ssh.ChannelMessage
}

func newMockChannelStream(t *testing.T) *mockChannelStream {
	cs := &mockChannelStream{
		GenericServerStream: &grpc.GenericServerStream[extensions_ssh.ChannelMessage, extensions_ssh.ChannelMessage]{
			ServerStream: &mockGrpcServerStream{
				ctx: t.Context(),
			},
		},
		serverToClient: make(chan *extensions_ssh.ChannelMessage, 32),
		clientToServer: make(chan *extensions_ssh.ChannelMessage, 32),
	}
	t.Cleanup(func() {
		cs.CloseClientToServer()
		cs.CloseServerToClient()
	})
	return cs
}

func (cs *mockChannelStream) Send(msg *extensions_ssh.ChannelMessage) error {
	cs.serverToClient <- msg
	return nil
}

func (cs *mockChannelStream) Recv() (*extensions_ssh.ChannelMessage, error) {
	msg, ok := <-cs.clientToServer
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

func (cs *mockChannelStream) SendClientToServer(msg *extensions_ssh.ChannelMessage) {
	cs.clientToServer <- msg
}

func (cs *mockChannelStream) CloseClientToServer() {
	cs.closeClientToServerOnce.Do(func() {
		close(cs.clientToServer)
	})
}

func (cs *mockChannelStream) CloseServerToClient() {
	cs.closeServerToClientOnce.Do(func() {
		close(cs.serverToClient)
	})
}

func (cs *mockChannelStream) RecvServerToClient() (*extensions_ssh.ChannelMessage, error) {
	select {
	case msg, ok := <-cs.serverToClient:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-time.After(DefaultTimeout):
		return nil, errors.New("timed out waiting for server to send message")
	}
}

var _ extensions_ssh.StreamManagement_ServeChannelServer = (*mockChannelStream)(nil)

func channelMsg(input any) *extensions_ssh.ChannelMessage {
	return &extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes(gossh.Marshal(input)),
		},
	}
}

func recvChannelMsg[T any](s *StreamHandlerSuite, stream *mockChannelStream) T {
	response, err := stream.RecvServerToClient()
	s.Require().NoError(err)
	var msg T
	s.Require().NoError(gossh.Unmarshal(response.GetRawBytes().GetValue(), &msg))
	return msg
}

func sendChannelMsg(stream *mockChannelStream, msg any) {
	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: &wrapperspb.BytesValue{
				Value: gossh.Marshal(msg),
			},
		},
	})
}

func (s *StreamHandlerSuite) TestServeChannel_InitialRecvError() {
	sh := s.startStreamHandler(1)

	stream := newMockChannelStream(s.T())
	stream.CloseClientToServer()
	s.Error(io.EOF, sh.ServeChannel(stream, &extensions_ssh.FilterMetadata{}))
}

func (s *StreamHandlerSuite) TestServeChannel_InitialRecvIsNotRawBytes() {
	sh := s.startStreamHandler(1)

	stream := newMockChannelStream(s.T())
	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_Metadata{},
	})
	s.ErrorIs(status.Errorf(codes.InvalidArgument, "first channel message was not ChannelOpen"),
		sh.ServeChannel(stream, &extensions_ssh.FilterMetadata{}))
}

func (s *StreamHandlerSuite) TestServeChannel_InitialRecvIsNotChannelOpen() {
	sh := s.startStreamHandler(1)

	stream := newMockChannelStream(s.T())
	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte("not ChannelOpen")),
		},
	})
	s.ErrorIs(status.Errorf(codes.InvalidArgument, "first channel message was not ChannelOpen"),
		sh.ServeChannel(stream, &extensions_ssh.FilterMetadata{}))
}

func init() {
	hook := func(s *StreamHandlerSuite, args []any) any {
		errorMatcher := args[0].(Matcher)
		sh := s.startStreamHandler(1)

		s.mockAuth.EXPECT().
			HandlePublicKeyMethodRequest(Any(), Any(), Any()).
			Times(1).
			DoAndReturn(func(_ context.Context, info ssh.StreamAuthInfo, req *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
				s.Equal("test", *info.Username)
				s.Equal("", *info.Hostname)
				return ssh.PublicKeyAuthMethodResponse{
					Allow: &extensions_ssh.PublicKeyAllowResponse{
						PublicKey:   req.PublicKey,
						Permissions: &extensions_ssh.Permissions{},
					},
					RequireAdditionalMethods: []string{},
				}, nil
			})
		s.False(sh.IsExpectingInternalChannel())
		sh.ReadC() <- &extensions_ssh.ClientMessage{
			Message: &extensions_ssh.ClientMessage_AuthRequest{
				AuthRequest: &extensions_ssh.AuthenticationRequest{
					Protocol:      "ssh",
					Service:       "ssh-connection",
					AuthMethod:    "publickey",
					Username:      "test",
					Hostname:      "",
					MethodRequest: s.validPublicKeyMethodRequest(),
				},
			},
		}
		s.expectAllowInternal(sh)
		s.True(sh.IsExpectingInternalChannel())
		s.Equal("test", *sh.Username())
		s.Equal("", *sh.Hostname())

		stream := newMockChannelStream(s.T())
		errC := make(chan error, 1)
		go func() {
			errC <- sh.ServeChannel(stream, &extensions_ssh.FilterMetadata{
				ChannelId: 1,
			})
			stream.CloseServerToClient()
		}()
		s.cleanup = append(s.cleanup, func() {
			stream.CloseClientToServer()
			select {
			case err := <-errC:
				s.Truef(errorMatcher.Matches(err), "expected: %v\nactual: %v", errorMatcher.String(), err)
			case <-time.After(DefaultTimeout):
				s.FailNow("timed out waiting for ServeChannel to exit")
			}
		})
		return stream
	}

	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_DifferentWindowAndPacketSizes"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_DirectTcpip_NoSubMsg"] = RuntimeFlagDependentHookWithArgs(hook,
		config.RuntimeFlagSSHAllowDirectTcpip, []any{Not(Nil())}, []any{Eq(status.Errorf(codes.Unavailable, "direct-tcpip channels are not enabled"))})
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_DirectTcpip_BadHostname"] = RuntimeFlagDependentHookWithArgs(hook,
		config.RuntimeFlagSSHAllowDirectTcpip, []any{Not(Nil())}, []any{Eq(status.Errorf(codes.Unavailable, "direct-tcpip channels are not enabled"))})
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_DirectTcpip_AuthFailed"] = RuntimeFlagDependentHookWithArgs(hook,
		config.RuntimeFlagSSHAllowDirectTcpip, []any{Eq(status.Errorf(codes.PermissionDenied, "test error"))}, []any{Eq(status.Errorf(codes.Unavailable, "direct-tcpip channels are not enabled"))})
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_DirectTcpip"] = RuntimeFlagDependentHookWithArgs(hook,
		config.RuntimeFlagSSHAllowDirectTcpip, []any{Nil()}, []any{Eq(status.Errorf(codes.Unavailable, "direct-tcpip channels are not enabled"))})
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_InvalidChannelType"] = HookWithArgs(hook, Eq(status.Errorf(codes.InvalidArgument, "unexpected channel type in ChannelOpen message: unknown")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_ExecWithPtyHelp"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_Exec_Whoami"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_Exec_WhoamiError"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_Exec_Logout"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_Exec_LogoutError"] = HookWithArgs(hook, Eq(status.Errorf(codes.Aborted, "failed to delete session")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal_NonInteractiveError"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortalDisabled_NoArgs"] = RuntimeFlagDependentHookWithArgs(hook,
		config.RuntimeFlagSSHRoutesPortal, []any{Not(Nil())}, []any{Eq(status.Errorf(codes.Canceled, "channel closed"))})
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_InteractiveError"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal_Select"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_ChannelCloseResponseTimeout"] = HookWithArgs(hook, Eq(status.Errorf(codes.DeadlineExceeded, "timed out waiting for channel close")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_HandleUnsupportedChannelRequests"] = HookWithArgs(hook, Eq(status.Errorf(codes.Canceled, "channel closed")))
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_HandleUnknownChannelRequest"] = HookWithArgs(hook, Eq(status.Errorf(codes.InvalidArgument, "unknown channel request: nonexistent")))
}

func (s *StreamHandlerSuite) TestServeChannel_Session() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	s.Equal(uint32(ssh.ChannelMaxPacket), resp.MaxPacketSize)
	s.Equal(uint32(ssh.ChannelWindowSize), resp.MyWindow)
	s.Equal(uint32(2), resp.PeersID)
	s.Equal(uint32(1), resp.MyID)
	sendChannelMsg(stream, ssh.ChannelCloseMsg{resp.MyID}) // server id
	recvChannelMsg[ssh.ChannelCloseMsg](s, stream)
}

func (s *StreamHandlerSuite) TestServeChannel_Session_DifferentWindowAndPacketSizes() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2, // client id
		PeersWindow:   ssh.ChannelWindowSize / 2,
		MaxPacketSize: ssh.ChannelMaxPacket / 2,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	s.Equal(uint32(ssh.ChannelMaxPacket), resp.MaxPacketSize)
	s.Equal(uint32(ssh.ChannelWindowSize), resp.MyWindow)
	s.Equal(uint32(2), resp.PeersID)                       // client id
	s.Equal(uint32(1), resp.MyID)                          // server id
	sendChannelMsg(stream, ssh.ChannelCloseMsg{resp.MyID}) // server id
	recvChannelMsg[ssh.ChannelCloseMsg](s, stream)
}

func (s *StreamHandlerSuite) channelDataLoop(peerID uint32, stream *mockChannelStream, exitCode ...uint32) *bytes.Buffer {
	s.T().Helper()
	var channelData bytes.Buffer
	for {
		response, err := stream.RecvServerToClient()
		if errors.Is(err, io.EOF) {
			break
		}
		s.Require().NoError(err)
		bytes := response.GetRawBytes().GetValue()
		switch bytes[0] {
		case ssh.MsgChannelData:
			var msg ssh.ChannelDataMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
			channelData.Write(msg.Rest)
		case ssh.MsgChannelExtendedData:
			var msg ssh.ChannelExtendedDataMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
			channelData.Write(msg.Rest)
		case ssh.MsgChannelRequest:
			var msg ssh.ChannelRequestMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
			s.Equal("exit-status", msg.Request)
			s.Require().NotEmpty(exitCode, "received an exit-status ChannelRequest but the test did not assert an exit code")
			expected := exitCode[0]
			actual := binary.BigEndian.Uint32(msg.RequestSpecificData)
			s.Equal(expected, actual)
		case ssh.MsgChannelClose:
			sendChannelMsg(stream, ssh.ChannelCloseMsg{PeersID: peerID})
		}
	}
	return &channelData
}

func (s *StreamHandlerSuite) TestServeChannel_Session_ExecWithPtyHelp() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:             peerID,
		Request:             "pty-req",
		WantReply:           true,
		RequestSpecificData: gossh.Marshal(ssh.PtyReqChannelRequestMsg{}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "--help",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	maybeRoutesPortalCmd := ""
	if s.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
		maybeRoutesPortalCmd = `  portal      Interactive route portal
`
	}
	channelData := s.channelDataLoop(peerID, stream, 0)
	// All newlines should be replaced with \r\n when a pty has been requested
	s.Equal(strings.ReplaceAll(`
Usage:
  pomerium [command]

Available Commands:
  help        Help about any command
  logout      Log out
`[1:]+maybeRoutesPortalCmd+
		`  whoami      Show details for the current session

Flags:
  -h, --help   help for pomerium

Use "pomerium [command] --help" for more information about a command.
`, "\n", "\r\n"), channelData.String())
}

func (s *StreamHandlerSuite) TestServeChannel_Session_ChannelCloseResponseTimeout() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:             peerID,
		Request:             "pty-req",
		WantReply:           true,
		RequestSpecificData: gossh.Marshal(ssh.PtyReqChannelRequestMsg{}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "--help",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)
	for {
		response, err := stream.RecvServerToClient()
		if errors.Is(err, io.EOF) {
			break
		}
		s.Require().NoError(err)
		bytes := response.GetRawBytes().GetValue()
		switch bytes[0] {
		case ssh.MsgChannelData:
			var msg ssh.ChannelDataMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
		case ssh.MsgChannelClose:
			// don't send a response
		}
	}
}

func (s *StreamHandlerSuite) TestServeChannel_Session_RoutesPortal_NonInteractiveError() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "shell",
		WantReply: true,
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	if s.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
		channelData := s.channelDataLoop(peerID, stream, 1)
		s.Equal("Error: 'portal' is an interactive command and requires a TTY (try passing '-t' to ssh)\n",
			ansi.Strip(channelData.String()))
	} else {
		channelData := s.channelDataLoop(peerID, stream, 0)
		s.Equal(`
Usage:
  pomerium [command]

Available Commands:
  help        Help about any command
  logout      Log out
  whoami      Show details for the current session

Flags:
  -h, --help   help for pomerium

Use "pomerium [command] --help" for more information about a command.
`[1:], channelData.String())
	}
}

func (s *StreamHandlerSuite) TestServeChannel_Session_RoutesPortalDisabled_NoArgs() {
	if s.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
		return
	}
	oldOsArgs := os.Args
	os.Args = []string{os.Args[0], "--nonexistent-flag"}
	defer func() {
		os.Args = oldOsArgs
	}()
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "shell",
		WantReply: true,
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	channelData := s.channelDataLoop(peerID, stream, 0)
	s.Equal(`
Usage:
  pomerium [command]

Available Commands:
  help        Help about any command
  logout      Log out
  whoami      Show details for the current session

Flags:
  -h, --help   help for pomerium

Use "pomerium [command] --help" for more information about a command.
`[1:], channelData.String())
}

func (s *StreamHandlerSuite) TestServeChannel_Session_InteractiveError() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:             peerID,
		Request:             "pty-req",
		WantReply:           true,
		RequestSpecificData: gossh.Marshal(ssh.PtyReqChannelRequestMsg{}),
	}))

	s.mockAuth.EXPECT().
		FormatSession(Any(), Any()).
		Return([]byte("foo\nbar\nbaz"), nil)

	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "whoami",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)
	channelData := s.channelDataLoop(peerID, stream, 0)
	s.Equal("foo\r\nbar\r\nbaz\r\n", channelData.String())
}

func printFrame(in string) string {
	re := strings.NewReplacer(" ", "·", "\t", "🡒", "\n", "\n⤶", "\r", "⇤")
	return re.Replace(ansi.Strip(in))
}

func postProcessFrame(in string) string {
	return strings.ReplaceAll(ansi.Strip(in), "\r", "")
}

type routesPortalTestHookOutput struct {
	stream *mockChannelStream
	peerID uint32
}

func init() {
	hook := func(s *StreamHandlerSuite) any {
		stream := s.BeforeTestHookResult.(*mockChannelStream)
		stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
			ChanType:      "session",
			PeersID:       2,
			PeersWindow:   ssh.ChannelWindowSize,
			MaxPacketSize: ssh.ChannelMaxPacket,
		}))
		resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
		peerID := resp.MyID
		stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
			PeersID:   peerID,
			Request:   "pty-req",
			WantReply: true,
			RequestSpecificData: gossh.Marshal(ssh.PtyReqChannelRequestMsg{
				TermEnv: "dumb",
				Width:   39,
				Height:  10,
			}),
		}))
		recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)
		stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
			PeersID:   peerID,
			Request:   "shell",
			WantReply: true,
		}))
		recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

		if !s.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
			channelData := s.channelDataLoop(peerID, stream, 0)
			s.Equal(strings.ReplaceAll(`
Usage:
  pomerium [command]

Available Commands:
  help        Help about any command
  logout      Log out
  whoami      Show details for the current session

Flags:
  -h, --help   help for pomerium

Use "pomerium [command] --help" for more information about a command.
`[1:], "\n", "\r\n"), channelData.String())
			return nil
		}
		return &routesPortalTestHookOutput{
			stream,
			peerID,
		}
	}
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal"] = append(StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal"], hook)
	StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal_Select"] = append(StreamHandlerSuiteBeforeTestHooks["TestServeChannel_Session_RoutesPortal_Select"], hook)
}

func (s *StreamHandlerSuite) TestServeChannel_Session_RoutesPortal() {
	res, _ := s.BeforeTestHookResult.(*routesPortalTestHookOutput)
	if res == nil {
		return // routes portal disabled
	}
	stream, peerID := res.stream, res.peerID

	frames := []string{
		`
||
|    Connect to which server?           |
|                                       |
|  > 1. test@host1                      |
|    2. test@host2                      |
|                                       |
|                                       |
|    ↑/k up • ↓/j down • q quit • ? more|
|                                       |`[1:],
		`
||
||
||
|    1. test@host1                      |
|  > 2. test@host2                      |
||
||
||
||`[1:],
	}
	for i, frame := range frames {
		frames[i] = strings.ReplaceAll(frame, "|", "")
	}
	var ok bool
	var channelData bytes.Buffer
	currentFrame := 0
	start := time.Now()
	frameAdvance := func() {
		switch currentFrame {
		case 0:
			cursorDown := []byte(ansi.CursorDown(1))
			currentFrame++
			sendChannelMsg(stream, ssh.ChannelDataMsg{
				PeersID: peerID,
				Length:  uint32(len(cursorDown)),
				Rest:    cursorDown,
			})
		case 1:
			currentFrame++
			ok = true
			sendChannelMsg(stream, ssh.ChannelDataMsg{
				PeersID: peerID,
				Length:  uint32(1),
				Rest:    []byte("q"),
			})
		}
		channelData.Reset()
	}
LOOP:
	for time.Since(start) < DefaultTimeout {
		response, err := stream.RecvServerToClient()
		if err != nil {
			s.Fail(err.Error())
			break
		}

		bytes := response.GetRawBytes().GetValue()
		switch bytes[0] {
		case ssh.MsgChannelData:
			if ok {
				continue
			}
			var msg ssh.ChannelDataMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
			channelData.Write(msg.Rest)
			if postProcessFrame(channelData.String()) == frames[currentFrame] {
				frameAdvance()
				if currentFrame >= len(frames) {
					ok = true
				}
			}
		case ssh.MsgChannelRequest:
			// the only channel request we expect to send would be "exit-status"
			var msg ssh.ChannelRequestMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
			s.Equal("exit-status", msg.Request)
			s.Equal(uint32(0), binary.BigEndian.Uint32(msg.RequestSpecificData))
		case ssh.MsgChannelClose:
			sendChannelMsg(stream, ssh.ChannelCloseMsg{PeersID: peerID})
			break LOOP
		default:
			s.FailNow("test bug")
		}
	}
	currentFrameStr := ""
	if !ok {
		currentFrameStr = printFrame(frames[currentFrame])
	}
	s.Require().Truef(ok, "timed out waiting for frame %d\nbuffer:\n%s\nexpecting:\n%s",
		currentFrame,
		printFrame(postProcessFrame(channelData.String())),
		currentFrameStr)
}

func (s *StreamHandlerSuite) TestServeChannel_Session_RoutesPortal_Select() {
	res, _ := s.BeforeTestHookResult.(*routesPortalTestHookOutput)
	if res == nil {
		return // routes portal disabled
	}
	stream, peerID := res.stream, res.peerID

	frames := []string{
		`
||
|    Connect to which server?           |
|                                       |
|  > 1. test@host1                      |
|    2. test@host2                      |
|                                       |
|                                       |
|    ↑/k up • ↓/j down • q quit • ? more|
|                                       |`[1:],
		`
||
||
||
|    1. test@host1                      |
|  > 2. test@host2                      |
||
||
||
||`[1:],
		`
||
|    Connect to which server?    |
|                                |
|    1. test@host1               |
|  > 2. test@host2               |
|                                |
|                                |
|    ↑/k up • ↓/j down • q quit …|
|                                |`[1:],
	}
	for i, frame := range frames {
		frames[i] = strings.ReplaceAll(frame, "|", "")
	}
	var portalOk bool
	var handoffOk bool
	var expectHandoff bool

	var channelData bytes.Buffer
	currentFrame := 0
	start := time.Now()
	frameAdvance := func() {
		switch currentFrame {
		case 0:
			cursorDown := []byte(ansi.CursorDown(1))
			currentFrame++
			sendChannelMsg(stream, ssh.ChannelDataMsg{
				PeersID: peerID,
				Length:  uint32(len(cursorDown)),
				Rest:    cursorDown,
			})
		case 1:
			currentFrame++

			sendChannelMsg(stream, ssh.ChannelRequestMsg{
				PeersID:   peerID,
				Request:   "window-change",
				WantReply: false,
				RequestSpecificData: gossh.Marshal(ssh.ChannelWindowChangeRequestMsg{
					WidthColumns: 36,
					HeightRows:   10,
				}),
			})
		case 2:
			currentFrame++
			s.mockAuth.EXPECT().EvaluateDelayed(Any(), Any()).
				DoAndReturn(func(_ context.Context, info ssh.StreamAuthInfo) error {
					s.Equal(info.Username, ptr("test"))
					s.Equal(info.Hostname, ptr("host2"))
					return nil
				})
			expectHandoff = true
			sendChannelMsg(stream, ssh.ChannelDataMsg{
				PeersID: peerID,
				Length:  uint32(1),
				Rest:    []byte("\r"),
			})
		}
		channelData.Reset()
	}
LOOP:
	for time.Since(start) < DefaultTimeout {
		response, err := stream.RecvServerToClient()
		if err != nil {
			s.Fail(err.Error())
			break
		}

		if expectHandoff {
			if response.GetRawBytes() != nil {
				// we might get bytes containing a newline
				var msg ssh.ChannelDataMsg
				s.Require().NoError(gossh.Unmarshal(response.GetRawBytes().GetValue(), &msg))
				s.Require().Empty(strings.TrimSpace(ansi.Strip(string(msg.Rest))))
				continue
			}
			action := response.GetChannelControl().GetControlAction()
			s.Require().NotNil(action, "expected channel control action")
			var sshAction extensions_ssh.SSHChannelControlAction
			s.Require().NoError(action.UnmarshalTo(&sshAction))
			handoff := sshAction.GetHandOff()
			s.Require().NotNil(action, "expected handoff action")
			s.Require().NotNil(handoff.GetUpstreamAuth().GetUpstream(), "expected upstream handoff action")
			s.Equal("test", handoff.GetUpstreamAuth().Username)
			s.Equal("host2", handoff.GetUpstreamAuth().GetUpstream().Hostname)
			testutil.AssertProtoEqual(s.T(), []*extensions_ssh.AllowedMethod{
				{
					Method: "publickey",
					MethodData: marshalAny(&extensions_ssh.PublicKeyAllowResponse{
						PublicKey:   s.ed25519SshPublicKey.Marshal(),
						Permissions: &extensions_ssh.Permissions{},
					}),
				},
			}, handoff.GetUpstreamAuth().GetUpstream().AllowedMethods)
			handoffOk = true
			break LOOP
		}

		bytes := response.GetRawBytes().GetValue()
		s.Require().NotNil(bytes, response.String())
		switch bytes[0] {
		case ssh.MsgChannelData:
			if portalOk {
				continue
			}
			s.Require().False(expectHandoff)

			var msg ssh.ChannelDataMsg
			s.Require().NoError(gossh.Unmarshal(bytes, &msg))
			channelData.Write(msg.Rest)
			if postProcessFrame(channelData.String()) == frames[currentFrame] {
				frameAdvance()
				if currentFrame >= len(frames) {
					portalOk = true
				}
			}
		default:
			s.FailNow("test bug")
		}
	}
	currentFrameStr := ""
	if !portalOk {
		currentFrameStr = printFrame(frames[currentFrame])
	}
	s.Truef(portalOk, "timed out waiting for frame %d\nbuffer:\n%s\nexpecting:\n%s",
		currentFrame,
		printFrame(postProcessFrame(channelData.String())),
		currentFrameStr)
	s.True(handoffOk, "timed out waiting for handoff")
	sendChannelMsg(stream, ssh.ChannelCloseMsg{PeersID: peerID})
}

func (s *StreamHandlerSuite) TestServeChannel_Session_Exec_Whoami() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID

	s.mockAuth.EXPECT().
		FormatSession(Any(), Any()).
		Return([]byte("example"), nil)

	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "whoami",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	channelData := s.channelDataLoop(peerID, stream, 0)
	s.Equal("example", channelData.String())
}

func (s *StreamHandlerSuite) TestServeChannel_Session_Exec_WhoamiError() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID

	s.mockAuth.EXPECT().
		FormatSession(Any(), Any()).
		Return(nil, errors.New("test error"))

	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "whoami",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	channelData := s.channelDataLoop(peerID, stream, 1)
	s.Equal("Error: couldn't fetch session: test error\n", channelData.String())
}

func (s *StreamHandlerSuite) TestServeChannel_Session_Exec_Logout() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID

	s.mockAuth.EXPECT().
		DeleteSession(Any(), Any()).
		Return(nil)

	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "logout",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	channelData := s.channelDataLoop(peerID, stream, 0)
	s.Equal("Logged out successfully\n", channelData.String())
}

func (s *StreamHandlerSuite) TestServeChannel_Session_Exec_LogoutError() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID

	s.mockAuth.EXPECT().
		DeleteSession(Any(), Any()).
		Return(status.Errorf(codes.Aborted, "failed to delete session"))

	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "exec",
		WantReply: true,
		RequestSpecificData: gossh.Marshal(ssh.ExecChannelRequestMsg{
			Command: "logout",
		}),
	}))
	recvChannelMsg[ssh.ChannelRequestSuccessMsg](s, stream)

	channelData := s.channelDataLoop(peerID, stream, 0)
	// The user will see this, but the error is propagated internally
	s.Equal("Logged out successfully\n", channelData.String())
	// error checked in cleanup
}

func (s *StreamHandlerSuite) TestServeChannel_DirectTcpip_NoSubMsg() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "direct-tcpip",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	// error checked in cleanup
}

func (s *StreamHandlerSuite) TestServeChannel_DirectTcpip_BadHostname() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "direct-tcpip",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
		TypeSpecificData: gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "", // invalid
			DestPort: 22,
			SrcAddr:  "127.0.0.1",
			SrcPort:  12345,
		}),
	}))
	// error checked in cleanup
}

func (s *StreamHandlerSuite) TestServeChannel_DirectTcpip_AuthFailed() {
	if s.directTcpipEnabled() {
		s.mockAuth.EXPECT().
			EvaluateDelayed(Any(), Any()).
			Times(1).
			Return(errors.New("test error"))
	}
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "direct-tcpip",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
		TypeSpecificData: gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "host1",
			DestPort: 22,
			SrcAddr:  "127.0.0.1",
			SrcPort:  12345,
		}),
	}))
	// error checked in cleanup
}

func (s *StreamHandlerSuite) TestServeChannel_DirectTcpip() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)

	if s.directTcpipEnabled() {
		s.mockAuth.EXPECT().
			EvaluateDelayed(Any(), Any()).
			Times(1).
			Return(nil)
	}
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "direct-tcpip",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
		TypeSpecificData: gossh.Marshal(ssh.ChannelOpenDirectMsg{
			DestAddr: "host1", // i.e. 'ssh -J pomerium test@host1'
			DestPort: 22,      // this will be sent by the ssh client, but is ignored
			SrcAddr:  "127.0.0.1",
			SrcPort:  12345,
		}),
	}))
	if !s.directTcpipEnabled() {
		return // error checked in cleanup
	}
	recv, err := stream.RecvServerToClient()

	s.Require().NoError(err)
	action := recv.GetChannelControl().GetControlAction()
	s.Require().NotNil(action, "received a message, but it was not a channel control action")
	handoff := extensions_ssh.SSHChannelControlAction{}
	s.Require().NoError(action.UnmarshalTo(&handoff))
	testutil.AssertProtoEqual(s.T(), extensions_ssh.SSHChannelControlAction_HandOffUpstream{
		DownstreamChannelInfo: &extensions_ssh.SSHDownstreamChannelInfo{
			ChannelType:               "direct-tcpip",
			DownstreamChannelId:       2,
			InternalUpstreamChannelId: 1,
			InitialWindowSize:         ssh.ChannelWindowSize,
			MaxPacketSize:             ssh.ChannelMaxPacket,
		},
		DownstreamPtyInfo: nil,
		UpstreamAuth: &extensions_ssh.AllowResponse{
			Username: "test",
			Target: &extensions_ssh.AllowResponse_Upstream{
				Upstream: &extensions_ssh.UpstreamTarget{
					Hostname:    "host1",
					DirectTcpip: true,
					AllowedMethods: []*extensions_ssh.AllowedMethod{
						{
							Method: "publickey",
							MethodData: marshalAny(&extensions_ssh.PublicKeyAllowResponse{
								PublicKey:   s.ed25519SshPublicKey.Marshal(),
								Permissions: &extensions_ssh.Permissions{},
							}),
						},
					},
				},
			},
		},
	}, handoff.GetHandOff())
}

func (s *StreamHandlerSuite) directTcpipEnabled() bool {
	return s.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHAllowDirectTcpip)
}

func (s *StreamHandlerSuite) TestServeChannel_HandleUnsupportedChannelRequests() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID

	requests := []string{"agent-req", "auth-agent-req@openssh.com", "env", "signal", "xon-xoff", "subsystem", "break", "eow@openssh.com"}

	for _, req := range requests {
		stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
			PeersID:   peerID,
			Request:   req,
			WantReply: false,
		}))
	}

	for _, req := range requests {
		stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
			PeersID:   peerID,
			Request:   req,
			WantReply: true,
		}))
		resp := recvChannelMsg[ssh.ChannelRequestFailureMsg](s, stream)
		s.Equal(uint32(2), resp.PeersID)
	}
	sendChannelMsg(stream, ssh.ChannelCloseMsg{PeersID: peerID})
}

func (s *StreamHandlerSuite) TestServeChannel_HandleUnknownChannelRequest() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "session",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	resp := recvChannelMsg[ssh.ChannelOpenConfirmMsg](s, stream)
	peerID := resp.MyID
	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{
		PeersID:   peerID,
		Request:   "nonexistent",
		WantReply: true,
	}))
}

func (s *StreamHandlerSuite) TestServeChannel_InvalidChannelType() {
	stream := s.BeforeTestHookResult.(*mockChannelStream)
	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{
		ChanType:      "unknown",
		PeersID:       2,
		PeersWindow:   ssh.ChannelWindowSize,
		MaxPacketSize: ssh.ChannelMaxPacket,
	}))
	// error checked in cleanup
}

func (s *StreamHandlerSuite) TestFormatSession() {
	s.mockAuth.EXPECT().
		FormatSession(Any(), Any()).
		Return([]byte("example"), nil)
	sh := s.mgr.NewStreamHandler(s.T().Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1})
	ctx, ca := context.WithCancel(context.Background())
	ca()
	// this will exit immediately, but it will have a state, which is only
	// created upon calling Run()
	sh.Run(ctx)

	res, err := sh.FormatSession(s.T().Context())
	s.NoError(err)
	s.Equal([]byte("example"), res)
}

func (s *StreamHandlerSuite) TestDeleteSession() {
	s.mockAuth.EXPECT().
		DeleteSession(Any(), Any()).
		Return(nil)
	sh := s.mgr.NewStreamHandler(s.T().Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1})
	ctx, ca := context.WithCancel(context.Background())
	ca()
	// this will exit immediately, but it will have a state, which is only
	// created upon calling Run()
	sh.Run(ctx)

	err := sh.DeleteSession(s.T().Context())
	s.NoError(err)
}

func (s *StreamHandlerSuite) TestRunCalledTwice() {
	sh := s.mgr.NewStreamHandler(s.T().Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1})
	ctx, ca := context.WithCancel(context.Background())
	ca()
	sh.Run(ctx)
	s.PanicsWithValue("Run called twice", func() {
		sh.Run(context.Background())
	})
}

func (s *StreamHandlerSuite) TestAllSSHRoutes() {
	sh := s.mgr.NewStreamHandler(s.T().Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1})
	routes := slices.Collect(sh.AllSSHRoutes())
	s.Len(routes, 2)
	s.Equal("ssh://host1", routes[0].From)
	s.Equal("ssh://dest1:22", routes[0].To[0].String())
	s.Equal("ssh://host2", routes[1].From)
	s.Equal("ssh://dest2:22", routes[1].To[0].String())

	next, stop := iter.Pull(sh.AllSSHRoutes())
	v, ok := next()
	s.NotNil(v)
	s.True(ok)
	stop()
	v, ok = next()
	s.Nil(v)
	s.False(ok)
}

func TestStreamHandlerSuite(t *testing.T) {
	suite.Run(t, &StreamHandlerSuite{})
}

func TestStreamHandlerSuiteWithRuntimeFlags(t *testing.T) {
	suite.Run(t, &StreamHandlerSuite{
		StreamHandlerSuiteOptions: StreamHandlerSuiteOptions{
			ConfigModifiers: []func(*config.Config){
				func(c *config.Config) {
					c.Options.RuntimeFlags[config.RuntimeFlagSSHRoutesPortal] = true
					c.Options.RuntimeFlags[config.RuntimeFlagSSHAllowDirectTcpip] = true
				},
			},
		},
	})
}

func ptr[T any](t T) *T {
	return &t
}
