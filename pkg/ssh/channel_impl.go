package ssh

import (
	"io"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/log"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type channelImpl struct {
	handler      *StreamHandler
	info         *extensions_ssh.SSHDownstreamChannelInfo
	stream       extensions_ssh.StreamManagement_ServeChannelServer
	remoteWindow *Window
	localWindow  uint32
}

// SendControlAction implements ChannelControlInterface.
func (cci *channelImpl) SendControlAction(action *extensions_ssh.SSHChannelControlAction) error {
	log.Ctx(cci.stream.Context()).Debug().Msg("sending channel control message")
	return cci.stream.Send(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_ChannelControl{
			ChannelControl: &extensions_ssh.ChannelControl{
				Protocol:      "ssh",
				ControlAction: marshalAny(action),
			},
		},
	})
}

// SendMessage implements ChannelControlInterface.
func (cci *channelImpl) SendMessage(msg any) error {
	switch msg := msg.(type) {
	case windowAdjustMsg, channelRequestMsg, channelRequestSuccessMsg, channelRequestFailureMsg, channelEOFMsg:
		// these messages don't consume window space
		data := gossh.Marshal(msg)
		if err := cci.stream.Send(&extensions_ssh.ChannelMessage{
			Message: &extensions_ssh.ChannelMessage_RawBytes{
				RawBytes: wrapperspb.Bytes(data),
			},
		}); err != nil {
			return err
		}
		log.Ctx(cci.stream.Context()).Debug().Uint8("type", data[0]).Msg("message sent")
		return nil
	default:
		data := gossh.Marshal(msg)
		need := uint32(len(data))
		have := uint32(0)
		for have < need {
			n, err := cci.remoteWindow.reserve(need - have)
			if err != nil {
				return err
			}
			have += n
		}
		if err := cci.stream.Send(&extensions_ssh.ChannelMessage{
			Message: &extensions_ssh.ChannelMessage_RawBytes{
				RawBytes: wrapperspb.Bytes(data),
			},
		}); err != nil {
			return err
		}
		log.Ctx(cci.stream.Context()).Debug().Uint8("type", data[0]).Uint32("size", need).Msg("message sent")
		return nil
	}
}

func (cci *channelImpl) RecvMsg() (any, error) {
	channelMsg, err := cci.stream.Recv()
	if err != nil {
		return nil, err
	}
	for {
		switch channelMsg := channelMsg.Message.(type) {
		case *extensions_ssh.ChannelMessage_RawBytes:
			msgLen := uint32(len(channelMsg.RawBytes.GetValue()))
			if msgLen == 0 {
				return nil, status.Errorf(codes.InvalidArgument, "peer sent empty message")
			}
			if msgLen > ChannelMaxPacket {
				return nil, status.Errorf(codes.ResourceExhausted, "message too large")
			}
			rawMsg := channelMsg.RawBytes.Value

			log.Ctx(cci.stream.Context()).
				Debug().
				Uint8("type", rawMsg[0]).
				Uint32("size", msgLen).
				Msg("message received")

			// peek the first byte to check if we need to deduct from the window
			switch rawMsg[0] {
			case msgChannelWindowAdjust, msgChannelRequest, msgChannelSuccess, msgChannelFailure, msgChannelEOF:
				// these messages don't consume window space
			default:
				if cci.localWindow < msgLen {
					return nil, status.Errorf(codes.ResourceExhausted, "peer sent more bytes than allowed by channel window")
				}
				cci.localWindow -= msgLen
				if cci.localWindow < ChannelWindowSize/2 {
					log.Ctx(cci.stream.Context()).Debug().Msg("flow control: increasing local window size")
					cci.localWindow += ChannelWindowSize
					if err := cci.SendMessage(windowAdjustMsg{
						PeersID:         cci.info.DownstreamChannelId,
						AdditionalBytes: ChannelWindowSize,
					}); err != nil {
						return nil, err
					}
				}
			}

			// decode the channel message
			switch rawMsg[0] {
			case msgChannelWindowAdjust:
				var msg windowAdjustMsg
				if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
					return nil, err
				}
				log.Ctx(cci.stream.Context()).Debug().Uint32("bytes", msg.AdditionalBytes).Msg("flow control: remote window size increased")
				cci.remoteWindow.add(msg.AdditionalBytes)
				// handle this internally and skip to the next message
				continue
			case msgChannelRequest:
				var msg channelRequestMsg
				if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
					return nil, err
				}
				return msg, nil
			case msgChannelData:
				var msg channelDataMsg
				if err := gossh.Unmarshal(rawMsg, &msg); err != nil {
					return nil, err
				}
				return msg, nil
			case msgChannelEOF:
				return nil, io.EOF
			case msgChannelOpen:
				return nil, status.Errorf(codes.InvalidArgument, "only one channel can be opened")
			default:
				return nil, status.Errorf(codes.Unimplemented, "received unknown message with type %d", rawMsg[0])
			}
		default:
			return nil, status.Errorf(codes.Unimplemented, "unknown channel message received")
		}
	}
}
