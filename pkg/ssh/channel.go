package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
)

type ChannelControlInterface interface {
	SendMessage(any) error
	RecvMsg() (any, error)
	SendControlAction(*extensions_ssh.SSHChannelControlAction) error
}

type ChannelHandler struct {
	ctrl ChannelControlInterface
}

func (c *ChannelHandler) Run(context context.Context) error {
	for {
		msg, err := c.ctrl.RecvMsg()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch msg := msg.(type) {
		case channelDataMsg:
			if err := c.handleChannelDataMsg(msg); err != nil {
				return err
			}
		case channelRequestMsg:
			if err := c.handleChannelRequestMsg(msg); err != nil {
				return err
			}
		default:
			panic(fmt.Sprintf("bug: unhandled message type: %T", msg))
		}
	}
}

func (c *ChannelHandler) handleChannelRequestMsg(msg channelRequestMsg) error {
	panic("unimplemented")
}

func (c *ChannelHandler) handleChannelDataMsg(msg channelDataMsg) error {
	panic("unimplemented")
}

func NewChannelHandler(ctrl ChannelControlInterface) *ChannelHandler {
	ch := &ChannelHandler{
		ctrl: ctrl,
	}
	return ch
}
