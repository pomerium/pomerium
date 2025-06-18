package ssh_test

import (
	"context"
	"math"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh"
)

func TestFlowControl_BlockAndWaitForAdjust(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})

	sendDone := make(chan struct{})
	wait := make(chan struct{})
	go func() {
		defer close(sendDone)
		close(wait)
		ci.SendMessage(ssh.ChannelDataMsg{
			PeersID: 1,
			Length:  1024,
			Rest:    make([]byte, 1024),
		})
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-wait
		stream.SendClientToServer(channelMsg(ssh.WindowAdjustMsg{
			PeersID:         2,
			AdditionalBytes: 1024,
		}))
		stream.SendClientToServer(channelMsg(ssh.ChannelDataMsg{
			PeersID: 2,
		}))
		msg, err := ci.RecvMsg()
		<-sendDone
		assert.NoError(t, err)
		assert.Equal(t, ssh.ChannelDataMsg{
			PeersID: 2,
			Rest:    []byte{},
		}, msg)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		assert.Fail(t, "timed out")
	}
}

func TestFlowControl_SendWindowAdjust(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})

	largeDataMsg := ssh.ChannelDataMsg{
		PeersID: 1,
		Length:  16375,
		Rest:    make([]byte, 16375),
	}
	encodedLen := len(gossh.Marshal(largeDataMsg))
	require.Equal(t, 16384, encodedLen) // to make the numbers easier

	const MaxMsgsSentBeforeAdjust = (ssh.ChannelWindowSize / 2) / 16384
	for i := range MaxMsgsSentBeforeAdjust {
		stream.SendClientToServer(channelMsg(largeDataMsg))
		dataMsg, err := ci.RecvMsg()
		assert.NoError(t, err)
		assert.NotNil(t, dataMsg)
		require.Equalf(t, 0, len(stream.serverToClient), "unexpected window adjust on message %d", i)
	}

	require.Equalf(t, 0, len(stream.serverToClient), "unexpected window adjust on message %d", MaxMsgsSentBeforeAdjust)
	stream.SendClientToServer(channelMsg(largeDataMsg))
	dataMsg, err := ci.RecvMsg()
	assert.NoError(t, err)
	assert.NotNil(t, dataMsg)
	require.Equal(t, 1, len(stream.serverToClient))

	recv, err := stream.RecvServerToClient()
	assert.NoError(t, err)
	bytes := recv.GetRawBytes().GetValue()
	var adjust ssh.WindowAdjustMsg
	assert.NoError(t, gossh.Unmarshal(bytes, &adjust))
	assert.Equal(t, uint32(ssh.ChannelWindowSize), adjust.AdditionalBytes)
	assert.Equal(t, uint32(1), adjust.PeersID)
}

func TestFlowControl_WindowAdjustOverflow(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})
	stream.SendClientToServer(channelMsg(ssh.WindowAdjustMsg{
		PeersID:         2,
		AdditionalBytes: math.MaxUint32,
	}))
	_, err := ci.RecvMsg()
	assert.ErrorIs(t, err, status.Errorf(codes.InvalidArgument, "invalid window adjustment"))
}

func TestFlowControl_StreamClosed(t *testing.T) {
	ctx, ca := context.WithCancel(t.Context())
	stream := &mockChannelStream{
		GenericServerStream: &grpc.GenericServerStream[extensions_ssh.ChannelMessage, extensions_ssh.ChannelMessage]{
			ServerStream: &mockGrpcServerStream{
				ctx: ctx,
			},
		},
		serverToClient: make(chan *extensions_ssh.ChannelMessage, 32),
		clientToServer: make(chan *extensions_ssh.ChannelMessage, 32),
	}
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         0,
		MaxPacketSize:             4096,
	})
	ready := make(chan struct{})
	errC := make(chan error, 1)
	go func() {
		close(ready)
		errC <- ci.SendMessage(ssh.ChannelDataMsg{
			PeersID: 1,
			Length:  1,
			Rest:    []byte("a"),
		})
	}()
	<-ready
	runtime.Gosched()
	ca()
	select {
	case err := <-errC:
		assert.ErrorIs(t, err, status.Errorf(codes.Internal, "stream closed"))
	case <-time.After(DefaultTimeout):
		assert.Fail(t, "timed out")
	}
}

func TestRecvMsg_EmptyMessage(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte{}),
		},
	})
	_, err := ci.RecvMsg()
	assert.ErrorIs(t, status.Errorf(codes.InvalidArgument, "peer sent empty message"), err)
}

func TestRecvMsg_MessageTooLarge(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})

	tooLargeDataMsg := ssh.ChannelDataMsg{
		PeersID: 1,
		Length:  ssh.ChannelMaxPacket,
		Rest:    make([]byte, ssh.ChannelMaxPacket),
	}
	stream.SendClientToServer(channelMsg(tooLargeDataMsg))
	_, err := ci.RecvMsg()
	assert.ErrorIs(t, status.Errorf(codes.ResourceExhausted, "message too large"), err)
}

func TestRecvMsg_AllowedMessages(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})

	// RecvMsg will immediately read another message after WindowAdjust, so
	// we have to send something
	stream.SendClientToServer(channelMsg(ssh.WindowAdjustMsg{}))
	stream.SendClientToServer(channelMsg(ssh.ChannelDataMsg{}))
	_, err := ci.RecvMsg()
	assert.NoError(t, err)

	stream.SendClientToServer(channelMsg(ssh.ChannelRequestMsg{}))
	_, err = ci.RecvMsg()
	assert.NoError(t, err)

	stream.SendClientToServer(channelMsg(ssh.ChannelDataMsg{}))
	_, err = ci.RecvMsg()
	assert.NoError(t, err)

	stream.SendClientToServer(channelMsg(ssh.ChannelCloseMsg{}))
	_, err = ci.RecvMsg()
	assert.NoError(t, err)

	stream.SendClientToServer(channelMsg(ssh.ChannelEOFMsg{}))
	_, err = ci.RecvMsg()
	assert.NoError(t, err)

	stream.SendClientToServer(channelMsg(ssh.ChannelOpenMsg{}))
	_, err = ci.RecvMsg()
	assert.ErrorIs(t, err, status.Errorf(codes.InvalidArgument, "only one channel can be opened"))

	stream.SendClientToServer(channelMsg(ssh.ChannelRequestFailureMsg{}))
	_, err = ci.RecvMsg()
	assert.ErrorIs(t, err, status.Errorf(codes.Unimplemented, "received unexpected message with type 100"))

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{Message: &extensions_ssh.ChannelMessage_ChannelControl{}})
	_, err = ci.RecvMsg()
	assert.ErrorIs(t, err, status.Errorf(codes.Unimplemented, "unknown channel message received"))
}

func TestRecvMsg_UnmarshalErrors(t *testing.T) {
	stream := newMockChannelStream(t)
	ci := ssh.NewChannelImpl(nil, stream, &extensions_ssh.SSHDownstreamChannelInfo{
		ChannelType:               "session",
		DownstreamChannelId:       1,
		InternalUpstreamChannelId: 2,
		InitialWindowSize:         1024,
		MaxPacketSize:             4096,
	})

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte{ssh.MsgChannelWindowAdjust}),
		},
	})
	_, err := ci.RecvMsg()
	assert.ErrorContains(t, err, "ssh: short read")

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte{ssh.MsgChannelRequest}),
		},
	})
	_, err = ci.RecvMsg()
	assert.ErrorContains(t, err, "ssh: short read")

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte{ssh.MsgChannelData}),
		},
	})
	_, err = ci.RecvMsg()
	assert.ErrorContains(t, err, "ssh: short read")

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte{ssh.MsgChannelClose}),
		},
	})
	_, err = ci.RecvMsg()
	assert.ErrorContains(t, err, "ssh: short read")

	stream.SendClientToServer(&extensions_ssh.ChannelMessage{
		Message: &extensions_ssh.ChannelMessage_RawBytes{
			RawBytes: wrapperspb.Bytes([]byte{ssh.MsgChannelEOF}),
		},
	})
	_, err = ci.RecvMsg()
	assert.ErrorContains(t, err, "ssh: short read")
}
