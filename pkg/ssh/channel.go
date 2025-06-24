package ssh

import (
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
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
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
	ctrl             ChannelControlInterface
	cli              *SshCli
	ptyInfo          *extensions_ssh.SSHDownstreamPTYInfo
	stdinR           io.Reader
	stdinW           io.Writer
	stdoutR          io.Reader
	stdoutW          io.WriteCloser
	cancel           context.CancelCauseFunc
	stdoutStreamDone chan struct{}

	sendChannelCloseMsgOnce sync.Once
}

func (ch *ChannelHandler) Run(ctx context.Context) error {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	ch.stdinR, ch.stdinW, ch.stdoutR, ch.stdoutW = stdinR, stdinW, stdoutR, stdoutW

	recvC := make(chan any)
	ctx, ch.cancel = context.WithCancelCause(ctx)
	go func() {
		for {
			msg, err := ch.ctrl.RecvMsg()
			if err != nil {
				ch.cancel(err)
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
			msg := channelDataMsg{
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

	for {
		select {
		case msg := <-recvC:
			switch msg := msg.(type) {
			case channelRequestMsg:
				if err := ch.handleChannelRequestMsg(ctx, msg); err != nil {
					return err
				}
			case channelDataMsg:
				if err := ch.handleChannelDataMsg(msg); err != nil {
					return err
				}
			case channelCloseMsg:
				ch.sendChannelCloseMsgOnce.Do(func() {
					ch.flushStdout()
					ch.sendChannelCloseMsg()
				})
				return status.Errorf(codes.Canceled, "channel closed")
			case channelEOFMsg:
				log.Ctx(ctx).Debug().Msg("received channel EOF")
			default:
				panic(fmt.Sprintf("bug: unhandled message type: %T", msg))
			}
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func (ch *ChannelHandler) flushStdout() {
	ch.stdoutW.Close()
	<-ch.stdoutStreamDone // ensure all output is written before sending the channel close message
}

func (ch *ChannelHandler) sendChannelCloseMsg() {
	ch.ctrl.SendMessage(channelCloseMsg{
		PeersID: ch.ctrl.DownstreamChannelID(),
	})
}

func (ch *ChannelHandler) initiateChannelClose(err error) {
	ch.sendChannelCloseMsgOnce.Do(func() {
		ch.flushStdout()
		ch.sendChannelCloseMsg()
		// the client needs to respond to our close request
		time.AfterFunc(1*time.Second, func() {
			ch.cancel(status.Errorf(codes.DeadlineExceeded, "timed out waiting for channel close"))
		})
	})
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
			err := ch.cli.ExecuteContext(ctx)
			if errors.Is(err, Handoff) {
				return // don't disconnect
			}
			ch.initiateChannelClose(err)
		}()
	case "pty-req":
		if ch.cli != nil || ch.ptyInfo != nil {
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
		if ch.cli == nil || ch.ptyInfo == nil {
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
	if msg.WantReply {
		ch.ctrl.SendMessage(channelRequestSuccessMsg{
			PeersID: ch.ctrl.DownstreamChannelID(),
		})
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
