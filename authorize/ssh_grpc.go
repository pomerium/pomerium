package authorize

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/storage"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type StreamState struct {
	Username             string
	Hostname             string
	PublicKey            []byte
	MethodsAuthenticated []string
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
		a.globalCache,
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

	var state StreamState

	//deviceAuthSuccess := &atomic.Bool{}
	sessionState := &atomic.Pointer[sessions.State]{}

	errC := make(chan error, 1)
	a.activeStreamsMu.Lock()
	a.activeStreams = append(a.activeStreams, errC)
	a.activeStreamsMu.Unlock()
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
					fmt.Println("downstream connected")
					_ = event
				case nil:
				}
			case *extensions_ssh.ClientMessage_AuthRequest:
				authReq := req.AuthRequest
				fmt.Println("auth request")
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

					if authReq.Username == "" && authReq.Hostname == "" {
						pkData, _ := anypb.New(publicKeyAllowResponse(state.PublicKey))
						resp := extensions_ssh.ServerMessage{
							Message: &extensions_ssh.ServerMessage_AuthResponse{
								AuthResponse: &extensions_ssh.AuthenticationResponse{
									Response: &extensions_ssh.AuthenticationResponse_Allow{
										Allow: &extensions_ssh.AllowResponse{
											Username: state.Username,
											Hostname: state.Hostname,
											AllowedMethods: []*extensions_ssh.AllowedMethod{
												{
													Method:     "publickey",
													MethodData: pkData,
												},
											},
											Target: extensions_ssh.Target_Internal,
										},
									},
								},
							},
						}
						sendC <- &resp
						continue
					}

					if session != nil {
						// Perform authorize check for this route
						req, err := a.getEvaluatorRequestFromSSHAuthRequest(&state)
						if err != nil {
							return err
						}
						res, err := a.evaluate(ctx, req, &sessions.State{ID: session.Id})
						if err != nil {
							return err
						}
						sendC <- handleEvaluatorResponseForSSH(res, &state)
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
					if route == nil {
						return fmt.Errorf("invalid route")
					}

					opts := a.currentOptions.Load()
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
						Prompts: []*extensions_ssh.KeyboardInteractiveInfoPrompts_Prompt{
							{},
						},
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
						err = a.PersistSession(ctx, s, claims, token)
						if err != nil {
							fmt.Println("error from PersistSession:", err)
							errC <- fmt.Errorf("error persisting session: %w", err)
							return
						}
						sessionState.Store(s)
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
				if sessionState.Load() != nil {
					state.MethodsAuthenticated = append(state.MethodsAuthenticated, "keyboard-interactive")
				} else {
					retryReq := extensions_ssh.KeyboardInteractiveInfoPrompts{
						Name:        "",
						Instruction: "Login not successful yet, try again",
						Prompts: []*extensions_ssh.KeyboardInteractiveInfoPrompts_Prompt{
							{},
						},
					}
					infoReqAny, _ := anypb.New(&retryReq)

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
					continue
				}

				if slices.Contains(state.MethodsAuthenticated, "publickey") {
					// Perform authorize check for this route
					req, err := a.getEvaluatorRequestFromSSHAuthRequest(&state)
					if err != nil {
						return err
					}
					res, err := a.evaluate(ctx, req, sessionState.Load())
					if err != nil {
						return err
					}
					sendC <- handleEvaluatorResponseForSSH(res, &state)
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

	return eg.Wait()
}

func (a *Authorize) getSSHRouteForHostname(hostname string) *config.Policy {
	opts := a.currentOptions.Load()
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
		return nil, fmt.Errorf("no route found for hostname %q", state.Hostname)
	}
	req := &evaluator.Request{
		IsInternal: false,
		HTTP: evaluator.RequestHTTP{
			Hostname: route.From, // XXX: this is not quite right
			//IP:     ?           // TODO
		},
		Session: evaluator.RequestSession{
			ID: sessionID,
		},
		Policy: route,
	}
	return req, nil
}

func handleEvaluatorResponseForSSH(
	result *evaluator.Result, state *StreamState,
) *extensions_ssh.ServerMessage {
	//fmt.Printf(" *** evaluator result: %+v\n", result)

	// TODO: ideally there would be a way to keep this in sync with the logic in check_response.go
	allow := result.Allow.Value && !result.Deny.Value

	if allow {
		pkData, _ := anypb.New(publicKeyAllowResponse(state.PublicKey))
		return &extensions_ssh.ServerMessage{
			Message: &extensions_ssh.ServerMessage_AuthResponse{
				AuthResponse: &extensions_ssh.AuthenticationResponse{
					Response: &extensions_ssh.AuthenticationResponse_Allow{
						Allow: &extensions_ssh.AllowResponse{
							Username: state.Username,
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
							//Target: extensions_ssh.Target_Upstream,
							Target: extensions_ssh.Target_Internal,
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
) error {
	now := time.Now()
	sessionLifetime := a.currentOptions.Load().CookieExpire
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
		return err
	}
	sessionState.DatabrokerServerVersion = res.GetServerVersion()
	sessionState.DatabrokerRecordVersion = res.GetRecord().GetVersion()

	return nil
}

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

func (a *Authorize) ServeChannel(
	server extensions_ssh.StreamManagement_ServeChannelServer,
) error {
	//inputR, inputW := io.Pipe()
	//outputR, outputW := io.Pipe()
	var peerId uint32

	var downstreamChannelInfo *extensions_ssh.SSHDownstreamChannelInfo
	var downstreamPtyInfo *extensions_ssh.SSHDownstreamPTYInfo

	handoff := func() error {
		handOff, _ := anypb.New(&extensions_ssh.SSHChannelControlAction{
			Action: &extensions_ssh.SSHChannelControlAction_HandOff{
				HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
					DownstreamChannelInfo: downstreamChannelInfo,
					DownstreamPtyInfo:     downstreamPtyInfo,
					UpstreamAuth: &extensions_ssh.AllowResponse{
						// XXX
						Username: "demo",
						Hostname: "ssh",
					},
				},
			},
		})
		return server.Send(&extensions_ssh.ChannelMessage{
			Message: &extensions_ssh.ChannelMessage_ChannelControl{
				ChannelControl: &extensions_ssh.ChannelControl{
					Protocol:      "ssh",
					ControlAction: handOff,
				},
			},
		})
	}

	for {
		channelMsg, err := server.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		rawMsg := channelMsg.GetRawBytes().GetValue()
		fmt.Printf(" *** channelMsg: %x\n", rawMsg)
		switch rawMsg[0] {
		case msgChannelOpen:
			var msg channelOpenMsg
			gossh.Unmarshal(rawMsg, &msg)

			var confirm channelOpenConfirmMsg
			peerId = msg.PeersID
			confirm.PeersID = peerId
			confirm.MyID = 1
			confirm.MyWindow = msg.PeersWindow
			confirm.MaxPacketSize = msg.MaxPacketSize
			downstreamChannelInfo = &extensions_ssh.SSHDownstreamChannelInfo{
				ChannelType:               msg.ChanType,
				DownstreamChannelId:       confirm.PeersID,
				InternalUpstreamChannelId: confirm.MyID,
				InitialWindowSize:         confirm.MyWindow,
				MaxPacketSize:             confirm.MaxPacketSize,
			}
			if err := server.Send(&extensions_ssh.ChannelMessage{
				Message: &extensions_ssh.ChannelMessage_RawBytes{
					RawBytes: &wrapperspb.BytesValue{
						Value: gossh.Marshal(confirm),
					},
				},
			}); err != nil {
				return err
			}

		case msgChannelRequest:
			var msg channelRequestMsg
			gossh.Unmarshal(rawMsg, &msg)

			fmt.Println(" *** SSH_MSG_CHANNEL_REQUEST: ", msg.Request)

			switch msg.Request {
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
			case "subsystem":
				subsystem := parseString(msg.RequestSpecificData)
				fmt.Println("     -> subsystem: ", subsystem)
				switch subsystem {
				case "pomerium-whoami":
					fmt.Println(" *** who am I? ***")
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
					if err := server.Send(&extensions_ssh.ChannelMessage{
						Message: &extensions_ssh.ChannelMessage_RawBytes{
							RawBytes: &wrapperspb.BytesValue{
								Value: gossh.Marshal(channelDataMsg{
									PeersID: peerId,
									Length:  uint32(12),
									Rest:    []byte("hello world!"),
								}),
							},
						},
					}); err != nil {
						return err
					}
					return nil // close the stream
				default:
					if err := handoff(); err != nil {
						return err
					}
				}
			default:
				// We're not interested in hijacking any other kinds of session.
				if err := handoff(); err != nil {
					return err
				}
			}

		case msgChannelData:
			var msg channelDataMsg
			gossh.Unmarshal(rawMsg, &msg)
			// ignore any data from the client (for now)

		case msgChannelClose:
			var msg channelDataMsg
			gossh.Unmarshal(rawMsg, &msg)

		default:
			panic("unhandled message: " + fmt.Sprint(rawMsg[1]))
		}
	}
}

/*func (a *Authorize) ServeChannel(
	server extensions_ssh.StreamManagement_ServeChannelServer,
) error {
	var program *tea.Program
	inputR, inputW := io.Pipe()
	outputR, outputW := io.Pipe()
	var peerId uint32

	var downstreamChannelInfo *extensions_ssh.SSHDownstreamChannelInfo
	var downstreamPtyInfo *extensions_ssh.SSHDownstreamPTYInfo
	for {
		channelMsg, err := server.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		rawMsg := channelMsg.GetRawBytes().GetValue()
		fmt.Printf(" *** channelMsg: %x\n", rawMsg)
		switch rawMsg[0] {
		case msgChannelOpen:
			var msg channelOpenMsg
			gossh.Unmarshal(rawMsg, &msg)

			var confirm channelOpenConfirmMsg
			peerId = msg.PeersID
			confirm.PeersID = peerId
			confirm.MyID = 1
			confirm.MyWindow = msg.PeersWindow
			confirm.MaxPacketSize = msg.MaxPacketSize
			downstreamChannelInfo = &extensions_ssh.SSHDownstreamChannelInfo{
				ChannelType:               msg.ChanType,
				DownstreamChannelId:       confirm.PeersID,
				InternalUpstreamChannelId: confirm.MyID,
				InitialWindowSize:         confirm.MyWindow,
				MaxPacketSize:             confirm.MaxPacketSize,
			}
			if err := server.Send(&extensions_ssh.ChannelMessage{
				Message: &extensions_ssh.ChannelMessage_RawBytes{
					RawBytes: &wrapperspb.BytesValue{
						Value: gossh.Marshal(confirm),
					},
				},
			}); err != nil {
				return err
			}

		case msgChannelRequest:
			var msg channelRequestMsg
			gossh.Unmarshal(rawMsg, &msg)

			fmt.Println(" *** SSH_MSG_CHANNEL_REQUEST: ", msg.Request)

			switch msg.Request {
			case "pty-req":
				req := parsePtyReq(msg.RequestSpecificData)
				items := []list.Item{
					item("ubuntu@vm"),
					item("joe@local"),
				}
				downstreamPtyInfo = &extensions_ssh.SSHDownstreamPTYInfo{
					TermEnv:      req.TermEnv,
					WidthColumns: req.Width,
					HeightRows:   req.Height,
					WidthPx:      req.WidthPx,
					HeightPx:     req.HeightPx,
					Modes:        req.Modes,
				}

				const defaultWidth = 20

				l := list.New(items, itemDelegate{}, defaultWidth, listHeight)
				l.Title = "Connect to which server?"
				l.SetShowStatusBar(false)
				l.SetFilteringEnabled(false)
				l.Styles.Title = titleStyle
				l.Styles.PaginationStyle = paginationStyle
				l.Styles.HelpStyle = helpStyle

				program = tea.NewProgram(model{list: l},
					tea.WithInput(inputR),
					tea.WithOutput(outputW),
					tea.WithAltScreen(),
					tea.WithContext(server.Context()),
					tea.WithEnvironment([]string{"TERM=" + req.TermEnv}),
				)
				go func() {
					answer, err := program.Run()
					if err != nil {
						return
					}
					username, hostname, _ := strings.Cut(answer.(model).choice, "@")
					handOff, _ := anypb.New(&extensions_ssh.SSHChannelControlAction{
						Action: &extensions_ssh.SSHChannelControlAction_HandOff{
							HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
								DownstreamChannelInfo: downstreamChannelInfo,
								DownstreamPtyInfo:     downstreamPtyInfo,
								UpstreamAuth: &extensions_ssh.AllowResponse{
									Username: username,
									Hostname: hostname,
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
						return
					}
				}()
				go func() {
					var buf [4096]byte
					for {
						n, err := outputR.Read(buf[:])
						if err != nil {
							return
						}
						if err := server.Send(&extensions_ssh.ChannelMessage{
							Message: &extensions_ssh.ChannelMessage_RawBytes{
								RawBytes: &wrapperspb.BytesValue{
									Value: gossh.Marshal(channelDataMsg{
										PeersID: peerId,
										Length:  uint32(n),
										Rest:    buf[:n],
									}),
								},
							},
						}); err != nil {
							return
						}
					}
				}()
				program.Send(tea.WindowSizeMsg{Width: int(req.Width), Height: int(req.Height)})

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
			}
		case msgChannelData:
			var msg channelDataMsg
			gossh.Unmarshal(rawMsg, &msg)

			if program != nil {
				inputW.Write(msg.Rest)
			}
		case msgChannelClose:
			var msg channelDataMsg
			gossh.Unmarshal(rawMsg, &msg)
		default:
			panic("unhandled message: " + fmt.Sprint(rawMsg[1]))
		}
	}
}*/

type ptyReq struct {
	TermEnv           string
	Width, Height     uint32
	WidthPx, HeightPx uint32
	Modes             []byte
}

func parseString(reqData []byte) string {
	stringLen := binary.BigEndian.Uint32(reqData)
	reqData = reqData[4:]
	return string(reqData[:stringLen])
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

const listHeight = 14

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
		m.list.SetWidth(msg.Width)
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
	if m.choice != "" {
		return quitTextStyle.Render(fmt.Sprintf("%s? Sounds good to me.", m.choice))
	}
	if m.quitting {
		return quitTextStyle.Render("Not hungry? That’s cool.")
	}
	return "\n" + m.list.View()
}
