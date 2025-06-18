package ssh

import (
	"context"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type ChannelImpl struct {
	StreamHandlerInterface
	info         *extensions_ssh.SSHDownstreamChannelInfo
	stream       extensions_ssh.StreamManagement_ServeChannelServer
	remoteWindow *Window
	localWindow  uint32
}

func NewChannelImpl(
	sh StreamHandlerInterface,
	stream extensions_ssh.StreamManagement_ServeChannelServer,
	info *extensions_ssh.SSHDownstreamChannelInfo,
) *ChannelImpl {
	remoteWindow := &Window{Cond: sync.NewCond(&sync.Mutex{})}
	remoteWindow.add(info.InitialWindowSize)
	context.AfterFunc(stream.Context(), func() {
		remoteWindow.close()
	})
	channel := &ChannelImpl{
		StreamHandlerInterface: sh,
		info:                   info,
		stream:                 stream,
		remoteWindow:           remoteWindow,
		localWindow:            ChannelWindowSize,
	}
	return channel
}

// SendControlAction implements ChannelControlInterface.
func (ci *ChannelImpl) SendControlAction(action *extensions_ssh.SSHChannelControlAction) error {
	log.Ctx(ci.stream.Context()).Debug().Msg("sending channel control message")
	return ci.stream.Send(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_ChannelControl{
			ChannelControl: &extensions_ssh.ChannelControl{
				Protocol:      "ssh",
				ControlAction: protoutil.NewAny(action),
			},
		},
	})
}

// SendMessage implements ChannelControlInterface.
func (ci *ChannelImpl) SendMessage(msg any) error {
	switch msg := msg.(type) {
	case ChannelOpenConfirmMsg, WindowAdjustMsg, ChannelRequestMsg,
		ChannelRequestSuccessMsg, ChannelRequestFailureMsg, ChannelEOFMsg:
		// these messages don't consume window space
		data := gossh.Marshal(msg)
		if err := ci.stream.Send(&extensions_ssh.ChannelMessage{
			Message: &extensions_ssh.ChannelMessage_RawBytes{
				RawBytes: wrapperspb.Bytes(data),
			},
		}); err != nil {
			return err
		}
		log.Ctx(ci.stream.Context()).Debug().Uint8("type", data[0]).Msg("message sent")
		return nil
	default:
		data := gossh.Marshal(msg)
		need := uint32(len(data))
		have := uint32(0)
		for have < need {
			n, err := ci.remoteWindow.reserve(need - have)
			if err != nil {
				return status.Errorf(codes.Internal, "stream closed")
			}
			have += n
		}
		if err := ci.stream.Send(&extensions_ssh.ChannelMessage{
			Message: &extensions_ssh.ChannelMessage_RawBytes{
				RawBytes: wrapperspb.Bytes(data),
			},
		}); err != nil {
			return err
		}
		log.Ctx(ci.stream.Context()).Debug().Uint8("type", data[0]).Uint32("size", need).Msg("message sent")
		return nil
	}
}

func (ci *ChannelImpl) RecvMsg() (any, error) {
	for {
		msgID, msg, err := ci.recvMsg()
		switch msgID {
		case MsgChannelWindowAdjust:
			// handle this internally and skip to the next message
			continue
		default:
			return msg, err
		}
	}
}

func (ci *ChannelImpl) recvMsg() (byte, any, error) {
	channelMsg, err := ci.stream.Recv()
	if err != nil {
		return 0, nil, err
	}
	switch channelMsg := channelMsg.Message.(type) {
	case *extensions_ssh.ChannelMessage_RawBytes:
		msgLen := uint32(len(channelMsg.RawBytes.GetValue()))
		if msgLen == 0 {
			return 0, nil, status.Errorf(codes.InvalidArgument, "peer sent empty message")
		}
		if msgLen > ChannelMaxPacket {
			return 0, nil, status.Errorf(codes.ResourceExhausted, "message too large")
		}
		rawMsg := channelMsg.RawBytes.Value

		log.Ctx(ci.stream.Context()).
			Debug().
			Uint8("type", rawMsg[0]).
			Uint32("size", msgLen).
			Msg("message received")

		// peek the first byte to check if we need to deduct from the window
		switch rawMsg[0] {
		case MsgChannelWindowAdjust, MsgChannelRequest, MsgChannelSuccess, MsgChannelFailure, MsgChannelEOF, MsgChannelClose:
			// these messages don't consume window space
		default:
			// NB: It is not possible for localWindow to be < msgLen, since the window
			// size is 64x the maximum packet size, and we have already checked the
			// packet size above. The window adjust message is sent when the window
			// size is at half of its max value.
			ci.localWindow -= msgLen
			if ci.localWindow < ChannelWindowSize/2 {
				log.Ctx(ci.stream.Context()).Debug().Msg("flow control: increasing local window size")
				ci.localWindow += ChannelWindowSize
				if err := ci.SendMessage(WindowAdjustMsg{
					PeersID:         ci.info.DownstreamChannelId,
					AdditionalBytes: ChannelWindowSize,
				}); err != nil {
					return 0, nil, err
				}
			}
		}

		// decode the channel message
		switch msgID := rawMsg[0]; msgID {
		case MsgChannelWindowAdjust:
			var msg WindowAdjustMsg
			if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
				return 0, nil, err
			}
			log.Ctx(ci.stream.Context()).Debug().Uint32("bytes", msg.AdditionalBytes).Msg("flow control: remote window size increased")
			if !ci.remoteWindow.add(msg.AdditionalBytes) {
				return 0, nil, status.Errorf(codes.InvalidArgument, "invalid window adjustment")
			}
			return msgID, msg, nil
		case MsgChannelRequest:
			var msg ChannelRequestMsg
			if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
				return 0, nil, err
			}
			return msgID, msg, nil
		case MsgChannelData:
			var msg ChannelDataMsg
			if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
				return 0, nil, err
			}
			return msgID, msg, nil
		case MsgChannelClose:
			var msg ChannelCloseMsg
			if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
				return 0, nil, err
			}
			return msgID, msg, nil
		case MsgChannelEOF:
			var msg ChannelEOFMsg
			if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
				return 0, nil, err
			}
			return msgID, msg, nil
		case MsgChannelOpen:
			return 0, nil, status.Errorf(codes.InvalidArgument, "only one channel can be opened")
		default:
			return 0, nil, status.Errorf(codes.Unimplemented, "received unexpected message with type %d", rawMsg[0])
		}
	default:
		return 0, nil, status.Errorf(codes.Unimplemented, "unknown channel message received")
	}
}
