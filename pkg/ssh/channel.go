package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type ChannelControlInterface interface {
	StreamHandlerInterface
	SendControlAction(*extensions_ssh.SSHChannelControlAction) error
	SendMessage(any) error
	RecvMsg() (any, error)
}

type StreamHandlerInterface interface {
	PrepareHandoff(ctx context.Context, hostname string, ptyInfo *extensions_ssh.SSHDownstreamPTYInfo) (*extensions_ssh.SSHChannelControlAction, error)
	FormatSession(ctx context.Context) ([]byte, error)
	DeleteSession(ctx context.Context) error
	AllSSHRoutes() iter.Seq[*config.Policy]
	Hostname() *string
	Username() *string
	DownstreamChannelID() uint32
}

type ChannelHandler struct {
	ctrl                    ChannelControlInterface
	config                  *config.Config
	cli                     *CLI
	ptyInfo                 *extensions_ssh.SSHDownstreamPTYInfo
	stdinR                  io.Reader
	stdinW                  io.Writer
	stdoutR                 io.Reader
	stdoutW                 io.WriteCloser
	stderrR                 io.Reader
	stderrW                 io.WriteCloser
	cancel                  context.CancelCauseFunc
	stdoutStreamDone        chan struct{}
	stderrStreamDone        chan struct{}
	sendChannelCloseMsgOnce sync.Once

	tuiDefaultMode      TUIDefaultMode
	deleteSessionOnExit bool

	portForwardStatusMu    sync.Mutex
	portForwardEndpoints   []portforward.RoutePortForwardInfo
	portForwardPermissions []*portforward.Permission
	portForwardRoutes      []portforward.RouteInfo
}

// OnClusterEndpointsUpdated implements portforward.UpdateListener.
func (ch *ChannelHandler) OnClusterEndpointsUpdated(endpoints []portforward.RoutePortForwardInfo) {
	ch.portForwardStatusMu.Lock()
	defer ch.portForwardStatusMu.Unlock()
	ch.portForwardEndpoints = endpoints
	if ch.cli != nil {
		ch.cli.SendTeaMsg(ch.portForwardEndpoints)
	}
}

// OnPermissionsUpdated implements portforward.UpdateListener.
func (ch *ChannelHandler) OnPermissionsUpdated(permissions *portforward.PermissionSet) {
	ch.portForwardStatusMu.Lock()
	defer ch.portForwardStatusMu.Unlock()
	list := make([]*portforward.Permission, 0, len(permissions.Permissions))
	for p := range permissions.Permissions {
		list = append(list, p)
	}
	ch.portForwardPermissions = list
	if ch.cli != nil {
		ch.cli.SendTeaMsg(ch.portForwardPermissions)
	}
}

// OnRoutesUpdated implements portforward.UpdateListener.
func (ch *ChannelHandler) OnRoutesUpdated(routes []portforward.RouteInfo) {
	ch.portForwardStatusMu.Lock()
	defer ch.portForwardStatusMu.Unlock()
	ch.portForwardRoutes = routes
	if ch.cli != nil {
		ch.cli.SendTeaMsg(routes)
	}
}

var ErrChannelClosed = status.Errorf(codes.Canceled, "channel closed")

func (ch *ChannelHandler) Run(ctx context.Context, tuiMode TUIDefaultMode) (retErr error) {
	defer func() {
		if ch.deleteSessionOnExit {
			ctx, ca := context.WithTimeout(context.Background(), 10*time.Second)
			defer ca()
			err := ch.ctrl.DeleteSession(ctx)
			if err != nil && errors.Is(retErr, ErrChannelClosed) {
				retErr = err
			}
		}
	}()
	ch.tuiDefaultMode = tuiMode
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	ch.stdinR, ch.stdinW, ch.stdoutR, ch.stdoutW, ch.stderrR, ch.stderrW = stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW

	recvC := make(chan any)
	ctx, ch.cancel = context.WithCancelCause(ctx)
	go func() {
		for {
			msg, err := ch.ctrl.RecvMsg()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					ch.cancel(err)
				}
				return
			}
			select {
			case recvC <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()
	ch.stdoutStreamDone = make(chan struct{})
	ch.stderrStreamDone = make(chan struct{})
	go func() {
		defer close(ch.stdoutStreamDone)
		var buf [4096]byte
		channelID := ch.ctrl.DownstreamChannelID()
		for {
			n, err := ch.stdoutR.Read(buf[:])
			if err != nil {
				if !errors.Is(err, io.EOF) {
					ch.cancel(err)
				}
				return
			}
			msg := ChannelDataMsg{
				PeersID: channelID,
				Length:  uint32(n),
				Rest:    slices.Clone(buf[:n]),
			}
			if err := ch.ctrl.SendMessage(msg); err != nil {
				ch.cancel(err)
				return
			}
		}
	}()
	go func() {
		defer close(ch.stderrStreamDone)
		var buf [4096]byte
		channelID := ch.ctrl.DownstreamChannelID()
		lastByteWrittenWasNewline := true
		for {
			n, err := ch.stderrR.Read(buf[:])
			if err != nil {
				if !errors.Is(err, io.EOF) {
					ch.cancel(err)
				}
				if ch.ptyInfo != nil && !lastByteWrittenWasNewline {
					ch.ctrl.SendMessage(ChannelExtendedDataMsg{
						PeersID:      channelID,
						DataTypeCode: 1, // SSH2_EXTENDED_DATA_STDERR
						Length:       2,
						Rest:         []byte{'\r', '\n'},
					})
				}
				return
			}
			lastByteWrittenWasNewline = (n > 0 && buf[n-1] == '\n')
			// Treat data written to stderr as if it should always have output
			// processing enabled. If the peer has requested a pty, assume it will
			// enable raw mode, disabling output processing. Emulate ONLCR (\n->\r\n)
			// mode here to make multiline text show up correctly.
			var rest []byte
			if ch.ptyInfo != nil {
				rest = bytes.ReplaceAll(buf[:n], []byte{'\n'}, []byte{'\r', '\n'})
			} else {
				rest = slices.Clone(buf[:n])
			}

			msg := ChannelExtendedDataMsg{
				PeersID:      channelID,
				DataTypeCode: 1, // SSH2_EXTENDED_DATA_STDERR
				Length:       uint32(len(rest)),
				Rest:         rest,
			}
			if err := ch.ctrl.SendMessage(msg); err != nil {
				ch.cancel(err)
				return
			}
		}
	}()

	for {
		select {
		case msg := <-recvC:
			switch msg := msg.(type) {
			case ChannelRequestMsg:
				if err := ch.handleChannelRequestMsg(ctx, msg); err != nil {
					ch.cancel(err)
				}
			case ChannelDataMsg:
				if err := ch.handleChannelDataMsg(msg); err != nil {
					ch.cancel(err)
				}
			case ChannelCloseMsg:
				ch.sendChannelCloseMsgOnce.Do(func() {
					ch.flushStdoutAndStderr()
					ch.sendChannelCloseMsg()
				})
				ch.cancel(ErrChannelClosed)
			case ChannelEOFMsg:
				log.Ctx(ctx).Debug().Msg("ssh: received channel EOF")
			default:
				panic(fmt.Sprintf("bug: unhandled message type: %T", msg))
			}
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func (ch *ChannelHandler) HandleEvent(event *extensions_ssh.ChannelEvent) {
	if ch.cli != nil {
		ch.cli.SendTeaMsg(event)
	}
}

func (ch *ChannelHandler) flushStdoutAndStderr() {
	ch.stdoutW.Close()
	ch.stderrW.Close()
	<-ch.stdoutStreamDone // ensure all output is written before sending the channel close message
	<-ch.stderrStreamDone
}

func (ch *ChannelHandler) sendChannelCloseMsg() {
	_ = ch.ctrl.SendMessage(ChannelCloseMsg{
		PeersID: ch.ctrl.DownstreamChannelID(),
	})
}

func (ch *ChannelHandler) sendExitStatus(err error) {
	var code byte
	if err != nil {
		code = 1
	}
	_ = ch.ctrl.SendMessage(ChannelRequestMsg{
		PeersID:             ch.ctrl.DownstreamChannelID(),
		Request:             "exit-status",
		WantReply:           false,
		RequestSpecificData: []byte{0x0, 0x0, 0x0, code},
	})
}

func (ch *ChannelHandler) initiateChannelClose(err error) {
	ch.sendChannelCloseMsgOnce.Do(func() {
		ch.flushStdoutAndStderr()
		ch.sendExitStatus(err)
		ch.sendChannelCloseMsg()
		// the client needs to respond to our close request before we send a
		// disconnect in order to get a clean exit, but if they don't respond in
		// a timely manner we will disconnect anyway
		time.AfterFunc(5*time.Second, func() {
			ch.cancel(status.Errorf(codes.DeadlineExceeded, "timed out waiting for channel close"))
		})
	})
}

func (ch *ChannelHandler) handleChannelRequestMsg(ctx context.Context, msg ChannelRequestMsg) error {
	switch msg.Request {
	case "shell", "exec":
		if ch.cli != nil {
			return status.Errorf(codes.FailedPrecondition, "unexpected channel request: %s", msg.Request)
		}
		ch.cli = NewCLI(ch.config, ch.ctrl, ch.ptyInfo, ch.stdinR, ch.stdoutW, ch.stderrW)
		switch msg.Request {
		case "shell":
			switch ch.tuiDefaultMode {
			case TUIModeInternalCLI:
				if ch.config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
					ch.cli.SetArgs([]string{"portal"})
				}
			case TUIModeTunnelStatus:
				ch.cli.SetArgs([]string{"tunnel"})
				ch.portForwardStatusMu.Lock()
				ch.cli.SendTeaMsg(ch.portForwardRoutes)
				ch.cli.SendTeaMsg(ch.portForwardEndpoints)
				ch.cli.SendTeaMsg(ch.portForwardPermissions)
				ch.portForwardStatusMu.Unlock()
			default:
				panic("invalid tui mode")
			}
		case "exec":
			var execReq ExecChannelRequestMsg
			if err := gossh.Unmarshal(msg.RequestSpecificData, &execReq); err != nil {
				return status.Errorf(codes.InvalidArgument, "malformed exec channel request")
			}
			ch.cli.SetArgs(strings.Fields(execReq.Command))
		}
		if msg.WantReply {
			if err := ch.sendChannelRequestSuccess(); err != nil {
				return err
			}
		}
		go func() {
			err := ch.cli.ExecuteContext(ctx)
			if errors.Is(err, ErrHandoff) {
				return // don't disconnect
			} else if errors.Is(err, ErrDeleteSessionOnExit) {
				ch.deleteSessionOnExit = true
				err = nil
			}
			ch.initiateChannelClose(err)
		}()
	case "pty-req":
		if ch.cli != nil || ch.ptyInfo != nil {
			return status.Errorf(codes.FailedPrecondition, "unexpected channel request: %s", msg.Request)
		}
		var ptyReq PtyReqChannelRequestMsg
		if err := gossh.Unmarshal(msg.RequestSpecificData, &ptyReq); err != nil {
			return status.Errorf(codes.InvalidArgument, "malformed pty-req channel request")
		}
		ch.ptyInfo = &extensions_ssh.SSHDownstreamPTYInfo{
			TermEnv:      ptyReq.TermEnv,
			WidthColumns: ptyReq.Width,
			HeightRows:   ptyReq.Height,
			WidthPx:      ptyReq.WidthPx,
			HeightPx:     ptyReq.HeightPx,
			Modes:        ptyReq.Modes,
		}
		if msg.WantReply {
			if err := ch.sendChannelRequestSuccess(); err != nil {
				return err
			}
		}
	case "window-change":
		if ch.cli == nil || ch.ptyInfo == nil {
			return status.Errorf(codes.InvalidArgument, "unexpected channel request: window-change")
		}
		var req ChannelWindowChangeRequestMsg
		if err := gossh.Unmarshal(msg.RequestSpecificData, &req); err != nil {
			return status.Errorf(codes.InvalidArgument, "malformed window-change channel request")
		}
		ch.cli.SendTeaMsg(tea.WindowSizeMsg{
			Width:  int(req.WidthColumns),
			Height: int(req.HeightRows),
		})
		// https://datatracker.ietf.org/doc/html/rfc4254#section-6.7:
		//  A response SHOULD NOT be sent to this message.
	case "agent-req", "auth-agent-req@openssh.com",
		"env", "signal", "xon-xoff", "subsystem", "break", "eow@openssh.com":
		// these can be ignored
		if msg.WantReply {
			log.Ctx(ctx).Debug().Str("request", msg.Request).Msg("ssh: rejecting unsupported channel request")
			if err := ch.sendChannelRequestFailure(); err != nil {
				return err
			}
		} else {
			log.Ctx(ctx).Debug().Str("request", msg.Request).Msg("ssh: ignoring unsupported channel request")
		}
	default:
		return status.Errorf(codes.InvalidArgument, "unknown channel request: %s", msg.Request)
	}
	return nil
}

func (ch *ChannelHandler) sendChannelRequestFailure() error {
	return ch.ctrl.SendMessage(ChannelRequestFailureMsg{
		PeersID: ch.ctrl.DownstreamChannelID(),
	})
}

func (ch *ChannelHandler) sendChannelRequestSuccess() error {
	return ch.ctrl.SendMessage(ChannelRequestSuccessMsg{
		PeersID: ch.ctrl.DownstreamChannelID(),
	})
}

func (ch *ChannelHandler) handleChannelDataMsg(msg ChannelDataMsg) error {
	if ch.cli == nil {
		return status.Errorf(codes.FailedPrecondition, "unexpected ChannelDataMsg")
	}
	_, err := ch.stdinW.Write(msg.Rest)
	if err != nil {
		return err
	}
	return nil
}

func NewChannelHandler(ctrl ChannelControlInterface, cfg *config.Config) *ChannelHandler {
	ch := &ChannelHandler{
		ctrl:   ctrl,
		config: cfg,
	}
	return ch
}
