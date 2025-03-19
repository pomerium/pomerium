package authorize

import (
	"bufio"
	"bytes"
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
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/klauspost/compress/zstd"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	extensions_session_recording "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh/filters/session_recording"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type StreamState struct {
	Username             string
	Hostname             string
	PublicKey            []byte
	MethodsAuthenticated []string
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

var activeStreamIds sync.Map

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

	deviceAuthSuccess := &atomic.Bool{}
	deviceAuthDone := make(chan struct{})

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
				case *extensions_ssh.StreamEvent_UpstreamConnected:
					fmt.Printf("upstream connected: %d\n", event.UpstreamConnected.GetStreamId())
					activeStreamIds.Store(event.UpstreamConnected.GetStreamId(), state)
					defer activeStreamIds.Delete(event.UpstreamConnected.GetStreamId())
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

					state.MethodsAuthenticated = append(state.MethodsAuthenticated, "publickey")
					state.PublicKey = pubkeyReq.PublicKey

					if authReq.Username == "" && authReq.Hostname == "" {
						resp := extensions_ssh.ServerMessage{
							Message: &extensions_ssh.ServerMessage_AuthResponse{
								AuthResponse: &extensions_ssh.AuthenticationResponse{
									Response: &extensions_ssh.AuthenticationResponse_Allow{
										Allow: &extensions_ssh.AllowResponse{
											Username: state.Username,
											Target: &extensions_ssh.AllowResponse_Internal{
												Internal: &extensions_ssh.InternalTarget{},
											},
										},
									},
								},
							},
						}
						sendC <- &resp
						continue
					} else if authReq.Username == "_mirror" && authReq.Hostname == "" {
						resp := extensions_ssh.ServerMessage{
							Message: &extensions_ssh.ServerMessage_AuthResponse{
								AuthResponse: &extensions_ssh.AuthenticationResponse{
									Response: &extensions_ssh.AuthenticationResponse_Allow{
										Allow: &extensions_ssh.AllowResponse{
											Username: state.Username,
											Target: &extensions_ssh.AllowResponse_Internal{
												Internal: &extensions_ssh.InternalTarget{},
											},
										},
									},
								},
							},
						}
						// id, _ := strconv.ParseUint(authReq.Hostname, 10, 64)
						// resp := extensions_ssh.ServerMessage{
						// 	Message: &extensions_ssh.ServerMessage_AuthResponse{
						// 		AuthResponse: &extensions_ssh.AuthenticationResponse{
						// 			Response: &extensions_ssh.AuthenticationResponse_Allow{
						// 				Allow: &extensions_ssh.AllowResponse{
						// 					Target: &extensions_ssh.AllowResponse_MirrorSession{
						// 						MirrorSession: &extensions_ssh.MirrorSessionTarget{
						// 							SourceId: id,
						// 							Mode:     extensions_ssh.MirrorSessionTarget_ReadWrite,
						// 						},
						// 					},
						// 				},
						// 			},
						// 		},
						// 	},
						// }
						sendC <- &resp
						continue
					} else if authReq.Username != "" && authReq.Hostname == "" {
						resp := extensions_ssh.ServerMessage{
							Message: &extensions_ssh.ServerMessage_AuthResponse{
								AuthResponse: &extensions_ssh.AuthenticationResponse{
									Response: &extensions_ssh.AuthenticationResponse_Allow{
										Allow: &extensions_ssh.AllowResponse{
											Username: state.Username,
											Target: &extensions_ssh.AllowResponse_Internal{
												Internal: &extensions_ssh.InternalTarget{},
											},
										},
									},
								},
							},
						}
						sendC <- &resp
						continue
					}

					if !slices.Contains(state.MethodsAuthenticated, "keyboard-interactive") {
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
					opts := a.currentOptions.Load()
					var route *config.Policy
					for r := range opts.GetAllPolicies() {
						if r.From == "ssh://"+strings.TrimSuffix(strings.Join([]string{state.Hostname, opts.SSHHostname}, "."), ".") {
							route = r
							break
						}
					}
					if route == nil {
						return fmt.Errorf("invalid route")
					}
					// sessionState := a.state.Load()

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
						Prompts:     []*extensions_ssh.KeyboardInteractiveInfoPrompts_Prompt{
							// {},
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
						err = claims.Claims.Claims(&s)
						if err != nil {
							errC <- fmt.Errorf("error unmarshaling session state: %w", err)
							return
						}
						fmt.Println(token)
						deviceAuthSuccess.Store(true)
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
				if deviceAuthSuccess.Load() {
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
					// retryReq := extensions_ssh.KeyboardInteractiveInfoPrompts{
					// 	Name:        "",
					// 	Instruction: "Login not successful yet, try again",
					// 	Prompts:     []*extensions_ssh.KeyboardInteractiveInfoPrompts_Prompt{
					// 		// {},
					// 	},
					// }
					// infoReqAny, _ := anypb.New(&retryReq)

					// resp := extensions_ssh.ServerMessage{
					// 	Message: &extensions_ssh.ServerMessage_AuthResponse{
					// 		AuthResponse: &extensions_ssh.AuthenticationResponse{
					// 			Response: &extensions_ssh.AuthenticationResponse_InfoRequest{
					// 				InfoRequest: &extensions_ssh.InfoRequest{
					// 					Method:  "keyboard-interactive",
					// 					Request: infoReqAny,
					// 				},
					// 			},
					// 		},
					// 	},
					// }
					// sendC <- &resp
					continue
				}
				if slices.Contains(state.MethodsAuthenticated, "publickey") {
					pkData, _ := anypb.New(&extensions_ssh.PublicKeyAllowResponse{
						PublicKey: state.PublicKey,
						Permissions: &extensions_ssh.Permissions{
							PermitPortForwarding:  true,
							PermitAgentForwarding: true,
							PermitX11Forwarding:   true,
							PermitPty:             true,
							PermitUserRc:          true,
							ValidBefore:           timestamppb.New(time.Now().Add(-1 * time.Minute)),
							ValidAfter:            timestamppb.New(time.Now().Add(12 * time.Hour)),
						},
					})
					sessionRecordingExt, _ := anypb.New(&extensions_session_recording.UpstreamTargetExtensionConfig{
						RecordingName: fmt.Sprintf("session-%s-at-%s-%d.cast", state.Username, state.Hostname, time.Now().UnixNano()),
						Format:        extensions_session_recording.Format_AsciicastFormat,
					})
					authResponse := extensions_ssh.ServerMessage{
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
					sendC <- &authResponse
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

type channelOpenDirectMsg struct {
	DestAddr string
	DestPort uint32
	SrcAddr  string
	SrcPort  uint32
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
			switch msg.ChanType {
			case "session":
				if err := server.Send(&extensions_ssh.ChannelMessage{
					Message: &extensions_ssh.ChannelMessage_RawBytes{
						RawBytes: &wrapperspb.BytesValue{
							Value: gossh.Marshal(confirm),
						},
					},
				}); err != nil {
					return err
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
			case "pty-req":
				opts := a.currentOptions.Load()
				var routes []string
				for r := range opts.GetAllPolicies() {
					if strings.HasPrefix(r.From, "ssh://") {
						routes = append(routes, fmt.Sprintf("ubuntu@%s", strings.TrimSuffix(strings.TrimPrefix(r.From, "ssh://"), "."+opts.SSHHostname)))
					}
				}
				req := parsePtyReq(msg.RequestSpecificData)
				items := []list.Item{}
				for _, route := range routes {
					items = append(items, item(route))
				}
				activeStreamIds.Range(func(key, value any) bool {
					items = append(items, item(fmt.Sprintf("[demo] mirror session: %v", key)))
					return true
				})
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
					var handOff *anypb.Any
					if strings.HasPrefix(answer.(model).choice, "[demo] mirror session: ") {
						id, err := strconv.ParseUint(strings.TrimPrefix(answer.(model).choice, "[demo] mirror session: "), 10, 64)
						if err != nil {
							panic(err)
						}
						handOff, _ = anypb.New(&extensions_ssh.SSHChannelControlAction{
							Action: &extensions_ssh.SSHChannelControlAction_HandOff{
								HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
									DownstreamChannelInfo: downstreamChannelInfo,
									DownstreamPtyInfo:     downstreamPtyInfo,
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
						sessionRecordingExt, _ := anypb.New(&extensions_session_recording.UpstreamTargetExtensionConfig{
							RecordingName: fmt.Sprintf("session-%s-at-%s-%d.cast", username, hostname, time.Now().UnixNano()),
							Format:        extensions_session_recording.Format_AsciicastFormat,
						})
						handOff, _ = anypb.New(&extensions_ssh.SSHChannelControlAction{
							Action: &extensions_ssh.SSHChannelControlAction_HandOff{
								HandOff: &extensions_ssh.SSHChannelControlAction_HandOffUpstream{
									DownstreamChannelInfo: downstreamChannelInfo,
									DownstreamPtyInfo:     downstreamPtyInfo,
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
	return "\n" + m.list.View()
}
