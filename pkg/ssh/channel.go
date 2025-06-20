package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	Hostname() string
	Username() string
	DownstreamChannelID() uint32
}

type ChannelHandler struct {
	ctrl                          ChannelControlInterface
	receivedInitialChannelRequest bool
	cli                           *SshCli
	ptyInfo                       *extensions_ssh.SSHDownstreamPTYInfo
	stdinR                        io.ReadCloser
	stdinW                        io.WriteCloser
	stdoutR                       io.ReadCloser
	stdoutW                       io.WriteCloser
}

func (ch *ChannelHandler) Run(ctx context.Context) error {
	ch.stdinR, ch.stdinW = io.Pipe()
	ch.stdoutR, ch.stdoutW = io.Pipe()

	go func() {
		var bytes []byte
		n, err := ch.stdoutR.Read(bytes)
		if err != nil {
			return
		}
		msg := channelDataMsg{
			PeersID: ch.ctrl.DownstreamChannelID(),
			Length:  uint32(n),
			Rest:    bytes,
		}
		if err := ch.ctrl.SendMessage(msg); err != nil {
			return
		}
	}()

	for {
		msg, err := ch.ctrl.RecvMsg()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch msg := msg.(type) {
		case channelRequestMsg:
			if err := ch.handleChannelRequestMsg(ctx, msg); err != nil {
				return err
			}
		case channelDataMsg:
			if err := ch.handleChannelDataMsg(msg); err != nil {
				return err
			}
		default:
			panic(fmt.Sprintf("bug: unhandled message type: %T", msg))
		}
	}
}

func (ch *ChannelHandler) handleChannelRequestMsg(ctx context.Context, msg channelRequestMsg) error {
	switch msg.Request {
	case "shell", "exec":
		if ch.cli != nil {
			return status.Errorf(codes.FailedPrecondition, "unexpected channel request: %s", msg.Request)
		}
		ch.cli = NewSshCli(ctx, ch.ctrl, ch.ptyInfo, ch.stdinR, ch.stdoutW)
		switch msg.Request {
		case "shell":
			ch.cli.SetArgs([]string{"portal"})
		case "exec":
			var execReq execChannelRequestMsg
			if err := gossh.Unmarshal(msg.RequestSpecificData, &execReq); err != nil {
				return status.Errorf(codes.InvalidArgument, "malformed exec channel request")
			}
			ch.cli.SetArgs(strings.Fields(execReq.Command))
		}
		go func() {
			defer ch.stdoutW.Close()
			defer ch.stdinR.Close()
			cliCtx, ca := context.WithCancel(ctx)
			err := ch.cli.ExecuteContext(cliCtx)
			ca()

			if !errors.Is(err, Handoff) {
				ch.ctrl.SendControlAction(&extensions_ssh.SSHChannelControlAction{
					Action: &extensions_ssh.SSHChannelControlAction_Disconnect_{
						Disconnect: &extensions_ssh.SSHChannelControlAction_Disconnect{
							ReasonCode:  11, // by application
							Description: err.Error(),
						},
					},
				})
			}
		}()
	case "pty-req":
		if ch.cli != nil {
			return status.Errorf(codes.FailedPrecondition, "unexpected channel request: %s", msg.Request)
		}
		var ptyReq ptyReqChannelRequestMsg
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
	case "window-change":
		if ch.cli == nil {
			return status.Errorf(codes.InvalidArgument, "unexpected channel request: window-change")
		}
		var req channelWindowChangeRequestMsg
		if err := gossh.Unmarshal(msg.RequestSpecificData, &req); err != nil {
			return status.Errorf(codes.InvalidArgument, "malformed window-change channel request")
		}
		ch.cli.SendTeaMsg(tea.WindowSizeMsg{
			Width:  int(req.WidthColumns),
			Height: int(req.HeightRows),
		})
	default:
		return status.Errorf(codes.InvalidArgument, "unknown channel request: %s", msg.Request)
	}
	return nil
}

func (ch *ChannelHandler) handleChannelDataMsg(msg channelDataMsg) error {
	if ch.cli == nil {
		return status.Errorf(codes.FailedPrecondition, "unexpected ChannelDataMsg")
	}
	_, err := ch.stdinW.Write(msg.Rest)
	if err != nil {
		return err
	}
	return nil
}

func NewChannelHandler(ctrl ChannelControlInterface) *ChannelHandler {
	ch := &ChannelHandler{
		ctrl: ctrl,
	}
	return ch
}
