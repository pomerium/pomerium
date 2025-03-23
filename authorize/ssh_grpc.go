package authorize

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/klauspost/compress/zstd"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	extensions_session_recording "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh/filters/session_recording"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type ActiveStreams struct {
	mu          sync.Mutex
	streamsById map[uint64]*StreamState
}

type StreamState struct {
	Context              context.Context
	StreamID             uint64
	ErrorC               chan<- error
	Username             string
	Hostname             string
	PublicKey            []byte
	MethodsAuthenticated []string
	Session              *session.Session
}

func (a *ActiveStreams) Get(id uint64) *StreamState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.streamsById[id]
}

func (a *ActiveStreams) Put(id uint64, state *StreamState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.streamsById[id] = state
}

func (a *ActiveStreams) Delete(id uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.streamsById, id)
}

func (a *ActiveStreams) Range(f func(id uint64, state *StreamState)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, state := range a.streamsById {
		f(id, state)
	}
}

func (a *Authorize) RecordingFinalized(
	stream grpc.ClientStreamingServer[extensions_session_recording.RecordingData, emptypb.Empty],
) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	md := msg.GetMetadata()
	if md == nil {
		return fmt.Errorf("first message did not contain metadata")
	}
	log.Ctx(stream.Context()).Info().Str("info", protojson.Format(md)).Msg("new recording")

	var recording []byte
READ:
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch data := msg.Data.(type) {
		case *extensions_session_recording.RecordingData_Chunk:
			recording = append(recording, data.Chunk...)
		case *extensions_session_recording.RecordingData_Checksum:
			actual := sha256.Sum256(recording)
			if actual != [32]byte(data.Checksum) {
				return fmt.Errorf("checksum mismatch")
			}
			break READ
		}
	}

	r, err := zstd.NewReader(bytes.NewReader(recording))
	if err != nil {
		return fmt.Errorf("failed to create zstd reader: %w", err)
	}

	switch md.Format {
	case extensions_session_recording.Format_AsciicastFormat:
		log.Ctx(stream.Context()).Info().Int("compressed_size", len(recording)).Msg("asciicast recording received")

		uncompressed, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("couldn't extract asciicast recording: %w", err)
		}

		// For demo purposes, store asciicast recordings in the databroker.
		_, err = a.state.Load().dataBrokerClient.Put(context.Background(), &databroker.PutRequest{
			Records: []*databroker.Record{
				{
					Type: "ssh-session-recording",
					Id:   md.RecordingName,
					Data: protoutil.NewAnyBytes(uncompressed),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("couldn't save asciicast recording: %w", err)
		}

	case extensions_session_recording.Format_RawFormat:
		reader := bufio.NewReader(r)
		var header extensions_session_recording.Header
		if err := protodelim.UnmarshalFrom(reader, &header); err != nil {
			return fmt.Errorf("failed to unmarshal header: %w", err)
		}

		var packets []*extensions_session_recording.Packet
		for {
			var packet extensions_session_recording.Packet
			err := protodelim.UnmarshalFrom(reader, &packet)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("failed to unmarshal packet: %w", err)
			}
			packets = append(packets, &packet)
		}

		log.Ctx(stream.Context()).Info().Int("compressed_size", len(recording)).Int("packet_count", len(packets)).Msg("recording received")
	}
	return nil
}

func (a *Authorize) ManageStream(
	server extensions_ssh.StreamManagement_ManageStreamServer,
) error {
	recvC := make(chan *extensions_ssh.ClientMessage, 32)
	sendC := make(chan *extensions_ssh.ServerMessage, 32)
	eg, ctx := errgroup.WithContext(server.Context())
	eg.Go(func() error {
		defer close(recvC)
		for {
			req, err := server.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			recvC <- req
		}
	})

	// XXX
	querier := storage.NewCachingQuerier(
		storage.NewQuerier(a.state.Load().dataBrokerClient),
		storage.GlobalCache,
	)
	ctx = storage.WithQuerier(ctx, querier)

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-sendC:
				if err := server.Send(msg); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
			}
		}
	})

	errC := make(chan error, 1)
	state := &StreamState{
		Context: ctx,
		ErrorC:  errC,
	}

	deviceAuthDone := make(chan struct{})
	for {
		select {
		case err := <-errC:
			return err
		case req, ok := <-recvC:
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
					state.StreamID = id
					a.activeStreams.Put(id, state)
					defer a.activeStreams.Delete(id)
				case *extensions_ssh.StreamEvent_UpstreamConnected:
				case nil:
				}
			case *extensions_ssh.ClientMessage_AuthRequest:
				authReq := req.AuthRequest
				if state.Username == "" {
					state.Username = authReq.Username
				}
				if state.Hostname == "" {
					state.Hostname = authReq.Hostname
				}
				switch authReq.AuthMethod {
				case "publickey":
					methodReq, _ := authReq.MethodRequest.UnmarshalNew()
					pubkeyReq, ok := methodReq.(*extensions_ssh.PublicKeyMethodRequest)
					if !ok {
						return fmt.Errorf("client sent invalid auth request message")
					}

					//
					// validate public key here
					//
					session, err := a.GetPomeriumSession(ctx, pubkeyReq.PublicKey)
					if err != nil {
						return err // XXX: wrap this error?
					}

					state.MethodsAuthenticated = append(state.MethodsAuthenticated, "publickey")
					state.PublicKey = pubkeyReq.PublicKey

					if authReq.Username == "" {
						return fmt.Errorf("no username given")
					}

					if session != nil {
						state.Session = session
						// Perform authorize check for this route
						req, err := a.getEvaluatorRequestFromSSHAuthRequest(state)
						if err != nil {
							return err
						}
						res, err := a.evaluate(ctx, req, &sessions.State{ID: session.Id})
						if err != nil {
							return err
						}
						sendC <- handleEvaluatorResponseForSSH(res, state)

						if res.Allow.Value && !res.Deny.Value {
							a.startContinuousAuthorization(ctx, errC, req, session)
						}
					}

					if session == nil && !slices.Contains(state.MethodsAuthenticated, "keyboard-interactive") {
						resp := extensions_ssh.ServerMessage{
							Message: &extensions_ssh.ServerMessage_AuthResponse{
								AuthResponse: &extensions_ssh.AuthenticationResponse{
									Response: &extensions_ssh.AuthenticationResponse_Deny{
										Deny: &extensions_ssh.DenyResponse{
											Partial: true,
											Methods: []string{"keyboard-interactive"},
										},
									},
								},
							},
						}
						sendC <- &resp
					}
				case "keyboard-interactive":
					route := a.getSSHRouteForHostname(state.Hostname)
					// route can be nil, in which case the default idp will be used

					opts := a.currentConfig.Load().Options
					idp, err := opts.GetIdentityProviderForPolicy(route)
					if err != nil {
						return err
					}
					authenticator, err := identity.NewAuthenticator(ctx, a.tracerProvider, oauth.Options{
						RedirectURL:          &url.URL{},
						ProviderName:         idp.GetType(),
						ProviderURL:          idp.GetUrl(),
						ClientID:             idp.GetClientId(),
						ClientSecret:         idp.GetClientSecret(),
						Scopes:               idp.GetScopes(),
						AuthCodeOptions:      idp.GetRequestParams(),
						DeviceAuthClientType: idp.GetDeviceAuthClientType(),
					})
					if err != nil {
						return err
					}
					deviceAuthResp, err := authenticator.DeviceAuth(ctx)
					if err != nil {
						return err
					}
					infoReq := extensions_ssh.KeyboardInteractiveInfoPrompts{
						Name:        "Sign in with " + idp.GetType(),
						Instruction: deviceAuthResp.VerificationURIComplete,
						Prompts:     []*extensions_ssh.KeyboardInteractiveInfoPrompts_Prompt{},
					}

					infoReqAny, _ := anypb.New(&infoReq)
					resp := extensions_ssh.ServerMessage{
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
					sendC <- &resp

					go func() {
						var claims identity.SessionClaims

						token, err := authenticator.DeviceAccessToken(ctx, deviceAuthResp, &claims)
						if err != nil {
							errC <- err
							return
						}
						s := sessions.NewState(idp.Id)
						claims.Claims.Claims(&s) // XXX
						s.ID, err = getSessionIDForSSH(state.PublicKey)
						if err != nil {
							errC <- err
							return
						}
						fmt.Println(token)
						state.Session, err = a.PersistSession(ctx, s, claims, token)
						if err != nil {
							fmt.Println("error from PersistSession:", err)
							errC <- fmt.Errorf("error persisting session: %w", err)
							return
						}
						close(deviceAuthDone)
					}()
				}
			case *extensions_ssh.ClientMessage_InfoResponse:
				resp := req.InfoResponse
				if resp.Method == "keyboard-interactive" {
					r, _ := resp.Response.UnmarshalNew()
					respInfo, ok := r.(*extensions_ssh.KeyboardInteractiveInfoPromptResponses)
					if ok {
						fmt.Println(respInfo.Responses)
					}
				}
				select {
				case <-deviceAuthDone:
				case <-ctx.Done():
				}
				if state.Session != nil {
					state.MethodsAuthenticated = append(state.MethodsAuthenticated, "keyboard-interactive")
				} else {
					resp := extensions_ssh.ServerMessage{
						Message: &extensions_ssh.ServerMessage_AuthResponse{
							AuthResponse: &extensions_ssh.AuthenticationResponse{
								Response: &extensions_ssh.AuthenticationResponse_Deny{
									Deny: &extensions_ssh.DenyResponse{},
								},
							},
						},
					}
					sendC <- &resp
					continue
				}

				if slices.Contains(state.MethodsAuthenticated, "publickey") {
					// Perform authorize check for this route
					req, err := a.getEvaluatorRequestFromSSHAuthRequest(state)
					if err != nil {
						return err
					}
					res, err := a.evaluate(ctx, req, &sessions.State{ID: state.Session.Id})
					if err != nil {
						return err
					}
					sendC <- handleEvaluatorResponseForSSH(res, state)

					if res.Allow.Value && !res.Deny.Value {
						a.startContinuousAuthorization(ctx, errC, req, state.Session)
					}
				} else {
					resp := extensions_ssh.ServerMessage{
						Message: &extensions_ssh.ServerMessage_AuthResponse{
							AuthResponse: &extensions_ssh.AuthenticationResponse{
								Response: &extensions_ssh.AuthenticationResponse_Deny{
									Deny: &extensions_ssh.DenyResponse{
										Partial: true,
										Methods: []string{"publickey"},
									},
								},
							},
						},
					}
					sendC <- &resp
				}

			case nil:
			}
		}
	}
}

func (a *Authorize) getSSHRouteForHostname(hostname string) *config.Policy {
	opts := a.currentConfig.Load().Options
	from := "ssh://" + strings.TrimSuffix(strings.Join([]string{hostname, opts.SSHHostname}, "."), ".")
	for r := range opts.GetAllPolicies() {
		if r.From == from {
			return r
		}
	}
	return nil
}

func (a *Authorize) GetPomeriumSession(
	ctx context.Context, publicKey []byte,
) (*session.Session, error) {
	sessionID, err := getSessionIDForSSH(publicKey)
	if err != nil {
		return nil, err
	}
	fmt.Println("session ID:", sessionID) // XXX

	session, err := session.Get(ctx, a.GetDataBrokerServiceClient(), sessionID)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	return session, nil
}

func getSessionIDForSSH(publicKey []byte) (string, error) {
	// XXX: get the fingerprint from Envoy rather than computing it here
	k, err := gossh.ParsePublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("couldn't parse ssh key: %w", err)
	}
	return "sshkey-" + gossh.FingerprintSHA256(k), nil
}

func (a *Authorize) getEvaluatorRequestFromSSHAuthRequest(
	state *StreamState,
) (*evaluator.Request, error) {
	sessionID, err := getSessionIDForSSH(state.PublicKey)
	if err != nil {
		return nil, err
	}
	route := a.getSSHRouteForHostname(state.Hostname)
	if route == nil {
		return &evaluator.Request{
			IsInternal: true,
			Session: evaluator.RequestSession{
				ID: sessionID,
			},
		}, nil

		// return nil, fmt.Errorf("no route found for hostname %q", state.Hostname)
	}
	req := &evaluator.Request{
		IsInternal: false,
		HTTP: evaluator.RequestHTTP{
			Hostname: route.From, // XXX: this is not quite right
			// IP:     ?           // TODO
		},
		Session: evaluator.RequestSession{
			ID: sessionID,
		},
		Policy: route,
	}
	return req, nil
}

func handleEvaluatorResponseForSSH(
	result *evaluator.Result,
	state *StreamState,
) *extensions_ssh.ServerMessage {
	// fmt.Printf(" *** evaluator result: %+v\n", result)

	// TODO: ideally there would be a way to keep this in sync with the logic in check_response.go
	allow := result.Allow.Value && !result.Deny.Value

	if allow {
		pkData, _ := anypb.New(publicKeyAllowResponse(state.PublicKey))

		if state.Hostname == "" {
			return &extensions_ssh.ServerMessage{
				Message: &extensions_ssh.ServerMessage_AuthResponse{
					AuthResponse: &extensions_ssh.AuthenticationResponse{
						Response: &extensions_ssh.AuthenticationResponse_Allow{
							Allow: &extensions_ssh.AllowResponse{
								Username: state.Username,
								Target: &extensions_ssh.AllowResponse_Internal{
									Internal: &extensions_ssh.InternalTarget{
										SetMetadata: &corev3.Metadata{
											FilterMetadata: map[string]*structpb.Struct{
												"pomerium": {
													Fields: map[string]*structpb.Value{
														"stream-id": structpb.NewStringValue(strconv.FormatUint(state.StreamID, 10)),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
		}
		sessionRecordingExt, _ := anypb.New(&extensions_session_recording.UpstreamTargetExtensionConfig{
			RecordingName: fmt.Sprintf("session-%s-at-%s-%d.cast", state.Username, state.Hostname, time.Now().UnixNano()),
			Format:        extensions_session_recording.Format_AsciicastFormat,
		})
		return &extensions_ssh.ServerMessage{
			Message: &extensions_ssh.ServerMessage_AuthResponse{
				AuthResponse: &extensions_ssh.AuthenticationResponse{
					Response: &extensions_ssh.AuthenticationResponse_Allow{
						Allow: &extensions_ssh.AllowResponse{
							Username: state.Username,
							Target: &extensions_ssh.AllowResponse_Upstream{
								Upstream: &extensions_ssh.UpstreamTarget{
									Hostname: state.Hostname,
									AllowedMethods: []*extensions_ssh.AllowedMethod{
										{
											Method:     "publickey",
											MethodData: pkData,
										},
										{
											Method: "keyboard-interactive",
										},
									},
									Extensions: []*corev3.TypedExtensionConfig{
										{
											TypedConfig: sessionRecordingExt,
										},
									},
								},
							},
						},
					},
				},
			},
		}
	}

	// XXX: do we want to send an equivalent to the "show error details" output
	//      in the case of a deny result?

	// XXX: this is not quite right -- needs to exactly match the last list of methods
	methods := []string{"publickey"}
	if slices.Contains(state.MethodsAuthenticated, "keyboard-interactive") {
		methods = append(methods, "keyboard-interactive")
	}

	return &extensions_ssh.ServerMessage{
		Message: &extensions_ssh.ServerMessage_AuthResponse{
			AuthResponse: &extensions_ssh.AuthenticationResponse{
				Response: &extensions_ssh.AuthenticationResponse_Deny{
					Deny: &extensions_ssh.DenyResponse{
						Methods: methods,
					},
				},
			},
		},
	}
}

func publicKeyAllowResponse(publicKey []byte) *extensions_ssh.PublicKeyAllowResponse {
	return &extensions_ssh.PublicKeyAllowResponse{
		PublicKey: publicKey,
		Permissions: &extensions_ssh.Permissions{
			PermitPortForwarding:  true,
			PermitAgentForwarding: true,
			PermitX11Forwarding:   true,
			PermitPty:             true,
			PermitUserRc:          true,
			ValidBefore:           timestamppb.New(time.Now().Add(-1 * time.Minute)),
			// XXX: tie this to Pomerium session lifetime?
			ValidAfter: timestamppb.New(time.Now().Add(12 * time.Hour)),
		},
	}
}

// PersistSession stores session and user data in the databroker.
func (a *Authorize) PersistSession(
	ctx context.Context,
	sessionState *sessions.State, // XXX: consider not using this struct
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) (*session.Session, error) {
	now := time.Now()
	sessionLifetime := a.currentConfig.Load().Options.CookieExpire
	sessionExpiry := timestamppb.New(now.Add(sessionLifetime))

	sess := &session.Session{
		Id:         sessionState.ID,
		UserId:     sessionState.UserID(),
		IssuedAt:   timestamppb.New(now),
		AccessedAt: timestamppb.New(now),
		ExpiresAt:  sessionExpiry,
		OauthToken: manager.ToOAuthToken(accessToken),
		Audience:   sessionState.Audience,
	}
	sess.SetRawIDToken(claims.RawIDToken)
	sess.AddClaims(claims.Flatten())

	// XXX: do we need to create a user record too?
	//      compare with Stateful.PersistSession()

	res, err := session.Put(ctx, a.GetDataBrokerServiceClient(), sess)
	if err != nil {
		return nil, err
	}
	sessionState.DatabrokerServerVersion = res.GetServerVersion()
	sessionState.DatabrokerRecordVersion = res.GetRecord().GetVersion()

	return sess, nil
}

func (a *Authorize) startContinuousAuthorization(
	ctx context.Context,
	errC chan<- error,
	req *evaluator.Request,
	session *session.Session,
) {
	recheck := func() {
		// XXX: probably want to log the results of this evaluation only if it changes
		res, _ := a.evaluate(ctx, req, &sessions.State{ID: session.Id})
		if !res.Allow.Value || res.Deny.Value {
			errC <- fmt.Errorf("no longer authorized")
		}
	}

	keyReq := &databroker.QueryRequest{
		Type:  grpcutil.GetTypeURL(session),
		Limit: 1,
	}
	keyReq.SetFilterByIDOrIndex(session.Id)
	key, err := (&proto.MarshalOptions{
		Deterministic: true,
	}).Marshal(keyReq)
	if err != nil {
		panic(err)
	}

	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-a.sessionsCacheWarmer.cache.Wait(key):
				errC <- fmt.Errorf("session expired")
				return
			case <-ticker.C:
				recheck()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func marshalAny(msg proto.Message) *anypb.Any {
	a, err := anypb.New(msg)
	if err != nil {
		panic(err)
	}
	return a
}

// sentinel error to indicate that the command triggered a handoff, and we
// should not automatically disconnect
var ErrHandoff = errors.New("handoff")

const loginScript = `` +
	`user="%[1]s"; ` +
	`if command -v getent >/dev/null 2>&1; then user_shell=$(getent passwd "$user" | cut -d: -f7); else user_shell="/bin/sh"; fi; ` +
	`shell_basename=$(basename "$user_shell"); ` +
	`if [ -z "$user_shell" ] || [ "$shell_basename" = "false" ] || [ "$shell_basename" = "nologin" ]; then ` +
	` if [ -x /bin/bash ]; then ` +
	`  user_shell="/bin/bash"; ` +
	` elif [ -x /bin/ash ]; then ` +
	`  user_shell="/bin/ash"; ` +
	` else ` +
	`  user_shell="/bin/sh"; ` +
	` fi; ` +
	`fi; ` +
	`exec /bin/su -s "$user_shell" "$user"`

func (a *Authorize) ServeChannel(
	server extensions_ssh.StreamManagement_ServeChannelServer,
) error {
	ctx := server.Context()
	inputR, inputW := io.Pipe()
	outputR, outputW := io.Pipe()
	var peerId uint32
	var activeProgram atomic.Pointer[tea.Program]
	var activeSizeQueue atomic.Pointer[terminalSizeQueue]

	errC := make(chan error, 1)
	remoteWindow := &window{Cond: sync.NewCond(&sync.Mutex{})}
	sendC := make(chan any, 8)
	recvC := make(chan *extensions_ssh.ChannelMessage)
	go func() {
		for {
			select {
			case msg := <-sendC:
				switch msg := msg.(type) {
				case *extensions_ssh.ChannelControl:
					log.Ctx(ctx).Debug().Msg("sending channel control message")
					if err := server.Send(&extensions_ssh.ChannelMessage{
						Message: &extensions_ssh.ChannelMessage_ChannelControl{
							ChannelControl: msg,
						},
					}); err != nil {
						errC <- err
						return
					}
				case windowAdjustMsg, channelRequestMsg, channelRequestSuccessMsg, channelRequestFailureMsg, channelEOFMsg:
					// these messages don't consume window space
					data := gossh.Marshal(msg)
					if err := server.Send(&extensions_ssh.ChannelMessage{
						Message: &extensions_ssh.ChannelMessage_RawBytes{
							RawBytes: wrapperspb.Bytes(data),
						},
					}); err != nil {
						errC <- err
						return
					}
					log.Ctx(ctx).Debug().Uint8("type", data[0]).Msg("message sent")
				default:
					data := gossh.Marshal(msg)
					need := uint32(len(data))
					have := uint32(0)
					for have < need {
						n, err := remoteWindow.reserve(need - have)
						if err != nil {
							errC <- err
							return
						}
						have += n
					}
					if err := server.Send(&extensions_ssh.ChannelMessage{
						Message: &extensions_ssh.ChannelMessage_RawBytes{
							RawBytes: wrapperspb.Bytes(data),
						},
					}); err != nil {
						errC <- err
						return
					}
					log.Ctx(ctx).Debug().Uint8("type", data[0]).Uint32("size", need).Msg("message sent")
				}
			case <-ctx.Done():
				errC <- ctx.Err()
				return
			}
		}
	}()

	var state *StreamState
	go func() {
		localWindow := uint32(channelWindowSize)
		for {
			channelMsg, err := server.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					errC <- nil
					return
				}
				errC <- err
				return
			}
			if state == nil {
				mdMsg, ok := channelMsg.Message.(*extensions_ssh.ChannelMessage_Metadata)
				if !ok {
					errC <- fmt.Errorf("first message was not metadata")
					return
				}
				idStr := mdMsg.Metadata.FilterMetadata["pomerium"].Fields["stream-id"].GetStringValue()
				if idStr == "" {
					errC <- fmt.Errorf("no session ID found for stream %q", idStr)
					return
				}
				id, err := strconv.ParseUint(idStr, 10, 64)
				if err != nil {
					errC <- fmt.Errorf("invalid stream ID %q: %w", idStr, err)
					return
				}
				if v := a.activeStreams.Get(id); v != nil {
					state = v
				} else {
					errC <- fmt.Errorf("no stream state found for ID %d", id)
					return
				}
				continue
			}
			if raw, ok := channelMsg.Message.(*extensions_ssh.ChannelMessage_RawBytes); ok {
				msgLen := uint32(len(raw.RawBytes.GetValue()))
				if msgLen == 0 {
					errC <- status.Errorf(codes.InvalidArgument, "peer sent empty message")
					return
				}
				if msgLen > channelMaxPacket {
					errC <- status.Errorf(codes.ResourceExhausted, "message too large")
					return
				}
				log.Ctx(ctx).Debug().Uint8("type", raw.RawBytes.Value[0]).Uint32("size", msgLen).Msg("message received")
				// peek the first byte to check if we need to deduct from the window
				switch raw.RawBytes.Value[0] {
				case msgChannelWindowAdjust, msgChannelRequest, msgChannelSuccess, msgChannelFailure, msgChannelEOF:
					// these messages don't consume window space
				default:
					if localWindow < msgLen {
						errC <- status.Errorf(codes.ResourceExhausted, "peer sent more bytes than allowed by channel window")
						return
					}
					localWindow -= msgLen
					if localWindow < channelWindowSize/2 {
						log.Ctx(ctx).Debug().Msg("flow control: increasing local window size")
						localWindow += channelWindowSize
						sendC <- windowAdjustMsg{
							PeersID:         peerId,
							AdditionalBytes: channelWindowSize,
						}
					}
				}
			}

			select {
			case recvC <- channelMsg:
			case <-ctx.Done():
				errC <- ctx.Err()
				return
			}
		}
	}()

	var downstreamChannelInfo *extensions_ssh.SSHDownstreamChannelInfo
	var downstreamPtyInfo *extensions_ssh.SSHDownstreamPTYInfo
	var channelIdCounter uint32
	for {
		select {
		case channelMsg := <-recvC:
			rawMsg := channelMsg.GetRawBytes().GetValue()
			switch rawMsg[0] {
			case msgChannelOpen:
				var msg channelOpenMsg
				gossh.Unmarshal(rawMsg, &msg)
				channelIdCounter++
				if channelIdCounter > 1 {
					return fmt.Errorf("only one channel can be opened")
				}
				peerId = msg.PeersID
				downstreamChannelInfo = &extensions_ssh.SSHDownstreamChannelInfo{
					ChannelType:               msg.ChanType,
					DownstreamChannelId:       peerId,
					InternalUpstreamChannelId: channelIdCounter,
					InitialWindowSize:         msg.PeersWindow,
					MaxPacketSize:             msg.MaxPacketSize,
				}
				remoteWindow.add(msg.PeersWindow)
				switch msg.ChanType {
				case "session":
					sendC <- channelOpenConfirmMsg{
						PeersID:       peerId,
						MyID:          channelIdCounter,
						MyWindow:      channelWindowSize,
						MaxPacketSize: channelMaxPacket,
					}
				case "direct-tcpip":
					var subMsg channelOpenDirectMsg
					if err := gossh.Unmarshal(msg.TypeSpecificData, &subMsg); err != nil {
						return err
					}
					handOff, _ := anypb.New(&extensions_ssh.SSHChannelControlAction{
						Action: &extensions_ssh.SSHChannelControlAction_HandOff{
							HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
								DownstreamChannelInfo: downstreamChannelInfo,
								UpstreamAuth: &extensions_ssh.AllowResponse{
									Target: &extensions_ssh.AllowResponse_Upstream{
										Upstream: &extensions_ssh.UpstreamTarget{
											Hostname:    subMsg.DestAddr,
											DirectTcpip: true,
										},
									},
								},
							},
						},
					})
					if err := server.Send(&extensions_ssh.ChannelMessage{
						Message: &extensions_ssh.ChannelMessage_ChannelControl{
							ChannelControl: &extensions_ssh.ChannelControl{
								Protocol:      "ssh",
								ControlAction: handOff,
							},
						},
					}); err != nil {
						return err
					}
				}

			case msgChannelRequest:
				var msg channelRequestMsg
				gossh.Unmarshal(rawMsg, &msg)

				switch msg.Request {
				case "shell", "exec":
					if err := server.Send(&extensions_ssh.ChannelMessage{
						Message: &extensions_ssh.ChannelMessage_RawBytes{
							RawBytes: &wrapperspb.BytesValue{
								Value: gossh.Marshal(channelRequestSuccessMsg{
									PeersID: peerId,
								}),
							},
						},
					}); err != nil {
						return err
					}

					if strings.Contains(state.Username, "://") {
						u, err := url.Parse(state.Username)
						if err == nil {
							switch u.Scheme {
							case "k8s":
								user := u.User.Username()
								_ = user
								pod, namespace, _ := strings.Cut(u.Hostname(), ".")
								// rules := clientcmd.NewDefaultClientConfigLoadingRules()
								// apiConfig, err := rules.Load()
								// if err != nil {
								// 	return err
								// }
								// conf, err := clientcmd.NewDefaultClientConfig(
								// 	*apiConfig, &clientcmd.ConfigOverrides{}).ClientConfig()
								conf, err := rest.InClusterConfig()
								if err != nil {
									return fmt.Errorf("no in-cluster config available")
								}
								client, err := kubernetes.NewForConfig(conf)
								if err != nil {
									return fmt.Errorf("failed to create kubernetes client: %w", err)
								}

								container := ""
								if u.Path != "" {
									container = strings.Trim(u.Path, "/")
									if strings.Contains(container, "/") {
										return fmt.Errorf("invalid container name %q", container)
									}
								}
								req := client.CoreV1().RESTClient().
									Get().
									Resource("pods").
									Namespace(namespace).
									Name(pod).
									SubResource("exec").
									VersionedParams(&corev1.PodExecOptions{
										Container: container,
										Command:   []string{"sh", "-c", fmt.Sprintf(loginScript, user)},
										Stdin:     true,
										Stdout:    true,
										Stderr:    true,
										TTY:       true,
									}, scheme.ParameterCodec)
								executor, err := remotecommand.NewWebSocketExecutor(conf, "GET", req.URL().String())
								if err != nil {
									return fmt.Errorf("failed to create executor: %w", err)
								}
								go streamOutputToChannel(sendC, peerId, outputR)
								go func() {
									defer outputW.Close()
									defer inputR.Close()
									sizeC := make(chan *remotecommand.TerminalSize, 64)
									sizeC <- &remotecommand.TerminalSize{
										Width:  uint16(downstreamPtyInfo.WidthColumns),
										Height: uint16(downstreamPtyInfo.HeightRows),
									}
									defer close(sizeC)
									queue := &terminalSizeQueue{C: sizeC}
									activeSizeQueue.Store(queue)
									defer activeSizeQueue.CompareAndSwap(queue, nil)
									err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
										Stdin:             inputR,
										Stdout:            outputW,
										Tty:               true,
										TerminalSizeQueue: queue,
									})
									if err != nil {
										errC <- err
									} else {
										sendC <- &extensions_ssh.ChannelControl{
											Protocol: "ssh",
											ControlAction: marshalAny(&extensions_ssh.SSHChannelControlAction_Disconnect{
												ReasonCode: 11,
											}),
										}
									}
								}()
								continue
							}
						}
					}
					cmd := a.NewSSHCLI(a.currentConfig.Load(), downstreamPtyInfo, downstreamChannelInfo, state, inputR, outputW, sendC, &activeProgram)
					if msg.Request == "shell" {
						cmd.SetArgs([]string{"portal"})
					} else {
						var execReq execChannelRequestMsg
						if err := gossh.Unmarshal(msg.RequestSpecificData, &execReq); err != nil {
							return err
						}
						cmd.SetArgs(strings.Fields(execReq.Command))
					}
					go func() {
						defer activeProgram.Store(nil)
						defer outputW.Close()
						defer inputR.Close()
						err := cmd.Execute()
						if !errors.Is(err, ErrHandoff) {
							sendC <- &extensions_ssh.ChannelControl{
								Protocol: "ssh",
								ControlAction: marshalAny(&extensions_ssh.SSHChannelControlAction_Disconnect{
									ReasonCode: 11,
								}),
							}
						}
					}()
					go streamOutputToChannel(sendC, peerId, outputR)

				case "pty-req":
					req := parsePtyReq(msg.RequestSpecificData)
					downstreamPtyInfo = &extensions_ssh.SSHDownstreamPTYInfo{
						TermEnv:      req.TermEnv,
						WidthColumns: req.Width,
						HeightRows:   req.Height,
						WidthPx:      req.WidthPx,
						HeightPx:     req.HeightPx,
						Modes:        req.Modes,
					}
					sendC <- channelRequestSuccessMsg{PeersID: peerId}
				case "window-change":
					var req channelWindowChangeRequestMsg
					if err := gossh.Unmarshal(msg.RequestSpecificData, &req); err != nil {
						return err
					}
					if p := activeProgram.Load(); p != nil {
						p.Send(tea.WindowSizeMsg{
							Width:  int(req.WidthColumns),
							Height: int(req.HeightRows),
						})
					} else if q := activeSizeQueue.Load(); q != nil {
						q.C <- &remotecommand.TerminalSize{
							Width:  uint16(req.WidthColumns),
							Height: uint16(req.HeightRows),
						}
					}
				}
			case msgChannelData:
				var msg channelDataMsg
				gossh.Unmarshal(rawMsg, &msg)
				inputW.Write(msg.Rest)
			case msgChannelClose:
				var msg channelDataMsg
				gossh.Unmarshal(rawMsg, &msg)
			case msgChannelWindowAdjust:
				var msg windowAdjustMsg
				if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
					return err
				}
				log.Ctx(ctx).Debug().Uint32("bytes", msg.AdditionalBytes).Msg("flow control: remote window size increased")
				remoteWindow.add(msg.AdditionalBytes)
			case msgChannelEOF:
				return nil
			default:
				panic("unhandled message: " + fmt.Sprint(rawMsg[1]))
			}
		case err := <-errC:
			log.Ctx(ctx).Err(err).Msg("channel error")
			return err
		}
	}
}

type terminalSizeQueue struct {
	C chan *remotecommand.TerminalSize
}

func (t *terminalSizeQueue) Next() *remotecommand.TerminalSize {
	return (<-t.C)
}

type ptyReq struct {
	TermEnv           string
	Width, Height     uint32
	WidthPx, HeightPx uint32
	Modes             []byte
}

func parsePtyReq(reqData []byte) ptyReq {
	termEnvLen := binary.BigEndian.Uint32(reqData)
	reqData = reqData[4:]
	termEnv := string(reqData[:termEnvLen])
	reqData = reqData[termEnvLen:]
	return ptyReq{
		TermEnv:  termEnv,
		Width:    binary.BigEndian.Uint32(reqData),
		Height:   binary.BigEndian.Uint32(reqData[4:]),
		WidthPx:  binary.BigEndian.Uint32(reqData[8:]),
		HeightPx: binary.BigEndian.Uint32(reqData[12:]),
		Modes:    reqData[16:],
	}
}

func streamOutputToChannel(sendC chan<- any, channelID uint32, outputR io.Reader) {
	var buf [4096]byte
	for {
		n, err := outputR.Read(buf[:])
		if err != nil {
			return
		}
		sendC <- channelDataMsg{
			PeersID: channelID,
			Length:  uint32(n),
			Rest:    slices.Clone(buf[:n]),
		}
	}
}

func (a *Authorize) NewSSHCLI(
	cfg *config.Config,
	ptyInfo *extensions_ssh.SSHDownstreamPTYInfo,
	channelInfo *extensions_ssh.SSHDownstreamChannelInfo,
	state *StreamState,
	stdin io.Reader,
	stdout io.Writer,
	sendC chan<- any,
	activeProgram *atomic.Pointer[tea.Program],
) *cobra.Command {
	cmd := &cobra.Command{
		Use: "pomerium",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			_, cmdIsInteractive := cmd.Annotations["interactive"]
			switch {
			case (ptyInfo == nil) && cmdIsInteractive:
				return fmt.Errorf("\x1b[31m'%s' is an interactive command and requires a TTY (try passing '-t' to ssh)\x1b[0m", cmd.Use)
			case (ptyInfo != nil) && !cmdIsInteractive:
				return fmt.Errorf("\x1b[31m'%s' is not an interactive command (try passing '-T' to ssh, or removing '-t')\x1b[0m\r", cmd.Use)
			}
			return nil
		},
	}
	sessionID := state.Session.Id
	cmd.AddCommand(a.NewPortalCommand(cfg, ptyInfo, channelInfo, state, sendC, activeProgram))
	cmd.AddCommand(a.NewLogoutCommand(cfg, sessionID))
	cmd.AddCommand(a.NewWhoamiCommand(cfg, sessionID))
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SilenceUsage = true
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	return cmd
}

func (a *Authorize) NewLogoutCommand(
	cfg *config.Config,
	sessionID string,
) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Log out",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := a.state.Load().dataBrokerClient
			err := session.Delete(cmd.Context(), client, sessionID)
			if err != nil {
				return fmt.Errorf("internal error: %w", err)
			}
			cmd.OutOrStdout().Write([]byte("Logged out successfully\r\n"))
			return nil
		},
	}
	return cmd
}

var whoamiTmpl = template.Must(template.New("whoami").Parse(`
User ID:    {{.UserId}}
Session ID: {{.Id}}
Expires at: {{.ExpiresAt.AsTime}}
Claims:
{{- range $k, $v := .Claims }}
  {{ $k }}: {{ $v.AsSlice }}
{{- end }}
`))

func (a *Authorize) NewWhoamiCommand(
	cfg *config.Config,
	sessionID string,
) *cobra.Command {
	cmd := &cobra.Command{
		Use: "whoami",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := a.state.Load().dataBrokerClient
			s, err := session.Get(cmd.Context(), client, sessionID)
			if err != nil {
				return fmt.Errorf("couldn't fetch session: %w", err)
			}
			var b bytes.Buffer
			whoamiTmpl.Execute(&b, s)
			cmd.OutOrStdout().Write([]byte(b.String() + "\r\n"))
			return nil
		},
	}
	return cmd
}

func (a *Authorize) NewPortalCommand(
	cfg *config.Config,
	ptyInfo *extensions_ssh.SSHDownstreamPTYInfo,
	channelInfo *extensions_ssh.SSHDownstreamChannelInfo,
	state *StreamState,
	sendC chan<- any,
	activeProgram *atomic.Pointer[tea.Program],
) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "portal",
		Short: "Interactive route portal",
		Annotations: map[string]string{
			"interactive": "",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var routes []string
			for r := range cfg.Options.GetAllPolicies() {
				if strings.HasPrefix(r.From, "ssh://") {
					routes = append(routes, fmt.Sprintf("%s@%s", state.Username, strings.TrimSuffix(strings.TrimPrefix(r.From, "ssh://"), "."+cfg.Options.SSHHostname)))
				}
			}
			items := []list.Item{}
			for _, route := range routes {
				items = append(items, item(route))
			}
			a.activeStreams.Range(func(id uint64, state *StreamState) {
				if id != state.StreamID {
					items = append(items, item(fmt.Sprintf("[demo] mirror session: %v", id)))
				}
			})

			l := list.New(items, itemDelegate{}, int(ptyInfo.WidthColumns-2), int(ptyInfo.HeightRows-2))
			l.Title = "Connect to which server?"
			l.SetShowStatusBar(false)
			l.SetFilteringEnabled(false)
			l.Styles.Title = titleStyle
			l.Styles.PaginationStyle = paginationStyle
			l.Styles.HelpStyle = helpStyle

			program := tea.NewProgram(model{list: l},
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
				tea.WithAltScreen(),
				tea.WithContext(cmd.Context()),
				tea.WithEnvironment([]string{"TERM=" + ptyInfo.TermEnv}),
			)
			activeProgram.Store(program)

			go program.Send(tea.WindowSizeMsg{Width: int(ptyInfo.WidthColumns), Height: int(ptyInfo.HeightRows)})
			answer, err := program.Run()
			if err != nil {
				return err
			}
			if answer.(model).choice == "" {
				return nil // quit/ctrl+c
			}
			var handOff *anypb.Any
			if strings.HasPrefix(answer.(model).choice, "[demo] mirror session: ") {
				id, err := strconv.ParseUint(strings.TrimPrefix(answer.(model).choice, "[demo] mirror session: "), 10, 64)
				if err != nil {
					panic(err)
				}
				handOff = marshalAny(&extensions_ssh.SSHChannelControlAction{
					Action: &extensions_ssh.SSHChannelControlAction_HandOff{
						HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
							DownstreamChannelInfo: channelInfo,
							DownstreamPtyInfo:     ptyInfo,
							UpstreamAuth: &extensions_ssh.AllowResponse{
								Target: &extensions_ssh.AllowResponse_MirrorSession{
									MirrorSession: &extensions_ssh.MirrorSessionTarget{
										SourceId: id,
										Mode:     extensions_ssh.MirrorSessionTarget_ReadWrite,
									},
								},
							},
						},
					},
				})
			} else {
				username, hostname, _ := strings.Cut(answer.(model).choice, "@")
				// Perform authorize check for this route
				state.Hostname = hostname
				if username != state.Username {
					return fmt.Errorf("internal error: username mismatch")
				}
				req, err := a.getEvaluatorRequestFromSSHAuthRequest(state)
				if err != nil {
					return err
				}
				res, err := a.evaluate(cmd.Context(), req, &sessions.State{ID: state.Session.Id})
				if err != nil {
					return err
				}

				if res.Allow.Value && !res.Deny.Value {
					a.startContinuousAuthorization(state.Context, state.ErrorC, req, state.Session)
				} else {
					return fmt.Errorf("not authorized")
				}
				sessionRecordingExt, _ := anypb.New(&extensions_session_recording.UpstreamTargetExtensionConfig{
					RecordingName: fmt.Sprintf("session-%s-at-%s-%d.cast", username, hostname, time.Now().UnixNano()),
					Format:        extensions_session_recording.Format_AsciicastFormat,
				})
				handOff = marshalAny(&extensions_ssh.SSHChannelControlAction{
					Action: &extensions_ssh.SSHChannelControlAction_HandOff{
						HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
							DownstreamChannelInfo: channelInfo,
							DownstreamPtyInfo:     ptyInfo,
							UpstreamAuth: &extensions_ssh.AllowResponse{
								Username: username,
								Target: &extensions_ssh.AllowResponse_Upstream{
									Upstream: &extensions_ssh.UpstreamTarget{
										AllowMirrorConnections: true,
										Hostname:               hostname,
										Extensions: []*corev3.TypedExtensionConfig{
											{
												TypedConfig: sessionRecordingExt,
											},
										},
									},
								},
							},
						},
					},
				})
			}

			sendC <- &extensions_ssh.ChannelControl{
				Protocol:      "ssh",
				ControlAction: handOff,
			}
			return ErrHandoff
		},
	}
	return cmd
}

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	quitTextStyle     = lipgloss.NewStyle().Margin(1, 0, 2, 4)
)

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type model struct {
	list     list.Model
	choice   string
	quitting bool
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width - 2)
		m.list.SetHeight(msg.Height - 2)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	return "\n" + m.list.View()
}

// code below copied from x/crypto/ssh/common.go

const (
	// channelMaxPacket contains the maximum number of bytes that will be
	// sent in a single packet. As per RFC 4253, section 6.1, 32k is also
	// the minimum.
	channelMaxPacket = 1 << 15
	// We follow OpenSSH here.
	channelWindowSize = 64 * channelMaxPacket
)

// window represents the buffer available to clients
// wishing to write to a channel.
type window struct {
	*sync.Cond
	win          uint32 // RFC 4254 5.2 says the window size can grow to 2^32-1
	writeWaiters int
	closed       bool
}

// add adds win to the amount of window available
// for consumers.
func (w *window) add(win uint32) bool {
	// a zero sized window adjust is a noop.
	if win == 0 {
		return true
	}
	w.L.Lock()
	if w.win+win < win {
		w.L.Unlock()
		return false
	}
	w.win += win
	// It is unusual that multiple goroutines would be attempting to reserve
	// window space, but not guaranteed. Use broadcast to notify all waiters
	// that additional window is available.
	w.Broadcast()
	w.L.Unlock()
	return true
}

// close sets the window to closed, so all reservations fail
// immediately.
func (w *window) close() {
	w.L.Lock()
	w.closed = true
	w.Broadcast()
	w.L.Unlock()
}

// reserve reserves win from the available window capacity.
// If no capacity remains, reserve will block. reserve may
// return less than requested.
func (w *window) reserve(win uint32) (uint32, error) {
	var err error
	w.L.Lock()
	w.writeWaiters++
	w.Broadcast()
	for w.win == 0 && !w.closed {
		w.Wait()
	}
	w.writeWaiters--
	if w.win < win {
		win = w.win
	}
	w.win -= win
	if w.closed {
		err = io.EOF
	}
	w.L.Unlock()
	return win, err
}

// code below copied from x/crypto/ssh/messages.go
// (with some additional messages not included there)

// See RFC 4254, section 5.1.
const msgChannelOpen = 90

type channelOpenMsg struct {
	ChanType         string `sshtype:"90"`
	PeersID          uint32
	PeersWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

const (
	msgChannelExtendedData = 95
	msgChannelData         = 94
)

// See RFC 4253, section 11.1.
const msgDisconnect = 1

// disconnectMsg is the message that signals a disconnect. It is also
// the error type returned from mux.Wait()
type disconnectMsg struct {
	Reason   uint32 `sshtype:"1"`
	Message  string
	Language string
}

// Used for debug print outs of packets.
type channelDataMsg struct {
	PeersID uint32 `sshtype:"94"`
	Length  uint32
	Rest    []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
const msgChannelOpenConfirm = 91

type channelOpenConfirmMsg struct {
	PeersID          uint32 `sshtype:"91"`
	MyID             uint32
	MyWindow         uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

const msgChannelRequest = 98

type channelRequestMsg struct {
	PeersID             uint32 `sshtype:"98"`
	Request             string
	WantReply           bool
	RequestSpecificData []byte `ssh:"rest"`
}

type channelOpenDirectMsg struct {
	DestAddr string
	DestPort uint32
	SrcAddr  string
	SrcPort  uint32
}

type channelWindowChangeRequestMsg struct {
	WidthColumns uint32
	HeightRows   uint32
	WidthPx      uint32
	HeightPx     uint32
}

type shellChannelRequestMsg struct{}

type execChannelRequestMsg struct {
	Command string
}

// See RFC 4254, section 5.2
const msgChannelWindowAdjust = 93

type windowAdjustMsg struct {
	PeersID         uint32 `sshtype:"93"`
	AdditionalBytes uint32
}

// See RFC 4254, section 5.4.
const msgChannelSuccess = 99

type channelRequestSuccessMsg struct {
	PeersID uint32 `sshtype:"99"`
}

// See RFC 4254, section 5.4.
const msgChannelFailure = 100

type channelRequestFailureMsg struct {
	PeersID uint32 `sshtype:"100"`
}

// See RFC 4254, section 5.3
const msgChannelClose = 97

type channelCloseMsg struct {
	PeersID uint32 `sshtype:"97"`
}

// See RFC 4254, section 5.3
const msgChannelEOF = 96

type channelEOFMsg struct {
	PeersID uint32 `sshtype:"96"`
}
