package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
)

type ChannelHandler struct {
	ctrl                    api.ChannelControlInterface
	cliCtrl                 cli.InternalCLIController
	config                  *config.Config
	cli                     *internalCLI
	cliMsgQueue             chan tea.Msg
	ptyInfo                 *extensions_ssh.SSHDownstreamPTYInfo
	stdinR                  io.ReadCloser
	stdinW                  io.Writer
	stdoutR                 io.Reader
	stdoutW                 io.WriteCloser
	stderrR                 io.Reader
	stderrW                 io.WriteCloser
	cancel                  context.CancelCauseFunc
	stdoutStreamDone        chan struct{}
	stderrStreamDone        chan struct{}
	sendChannelCloseMsgOnce sync.Once

	modeHint            extensions_ssh.InternalCLIModeHint
	deleteSessionOnExit bool
}

var ErrChannelClosed = status.Errorf(codes.Canceled, "channel closed")

func (ch *ChannelHandler) Run(ctx context.Context, tuiMode extensions_ssh.InternalCLIModeHint) (retErr error) {
	defer func() {
		close(ch.cliMsgQueue)
		if ch.deleteSessionOnExit {
			ctx, ca := context.WithTimeout(context.Background(), 10*time.Second)
			defer ca()
			err := ch.ctrl.DeleteSession(ctx)
			if err != nil && errors.Is(retErr, ErrChannelClosed) {
				retErr = err
			}
		}
	}()
	ch.modeHint = tuiMode
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
			rest := slices.Clone(buf[:n])
			// temporary workaround due to bug in bubbletea renderer
			rest = bytes.ReplaceAll(rest, []byte{'\r', '\n'}, []byte{'\n'})
			rest = bytes.ReplaceAll(rest, []byte{'\n'}, []byte{'\r', '\n'})
			msg := ChannelDataMsg{
				PeersID: channelID,
				Length:  uint32(len(rest)),
				Rest:    rest,
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
					_ = ch.ctrl.SendMessage(ChannelExtendedDataMsg{
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

func (ch *ChannelHandler) OnDiagnosticsReceived(diagnostics []*extensions_ssh.Diagnostic) {
	for _, diag := range diagnostics {
		ch.cliMsgQueue <- diag
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
		ch.cli = newInternalCLI(ch.ptyInfo, ch.cliMsgQueue, ch.stdinR, ch.stdoutW, ch.stderrW)
		ch.cliCtrl.Configure(ch.cli.Command, ch.cli, ch.ctrl)
		switch msg.Request {
		case "shell":
			ch.cli.SetArgs(ch.cliCtrl.DefaultArgs(ch.modeHint))

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
			ch.stdinR.Close()
			if errors.Is(err, cli.ErrHandoff) {
				return // don't disconnect
			} else if errors.Is(err, cli.ErrDeleteSessionOnExit) {
				ch.deleteSessionOnExit = true
				err = nil
				fmt.Fprintln(ch.cli.stderr, "Logged out successfully")
			} else if err != nil {
				fmt.Fprintf(ch.cli.stderr, "Error: %s\n", err.Error())
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
		ch.cliMsgQueue <- tea.WindowSizeMsg{
			Width:  int(req.WidthColumns),
			Height: int(req.HeightRows),
		}
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

func NewChannelHandler(ctrl api.ChannelControlInterface, cliCtrl cli.InternalCLIController, cfg *config.Config) *ChannelHandler {
	ch := &ChannelHandler{
		ctrl:        ctrl,
		cliCtrl:     cliCtrl,
		config:      cfg,
		cliMsgQueue: make(chan tea.Msg, 256),
	}
	return ch
}
