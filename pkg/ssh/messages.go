// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import "fmt"

// Unexported message types copied from x/crypto/ssh

// See RFC 4254, section 5.1.
const MsgChannelOpen = 90

type ChannelOpenMsg struct {
	ChanType         string `sshtype:"90"`
	PeersID          uint32
	PeersWindow      uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

const (
	MsgChannelExtendedData = 95
	MsgChannelData         = 94
)

// See RFC 4253, section 11.1.
const MsgDisconnect = 1

// DisconnectMsg is the message that signals a disconnect. It is also
// the error type returned from mux.Wait()
type DisconnectMsg struct {
	Reason   uint32 `sshtype:"1"`
	Message  string
	Language string
}

type ChannelDataMsg struct {
	PeersID uint32 `sshtype:"94"`
	Length  uint32
	Rest    []byte `ssh:"rest"`
}

type ChannelExtendedDataMsg struct {
	PeersID      uint32 `sshtype:"95"`
	DataTypeCode uint32
	Length       uint32
	Rest         []byte `ssh:"rest"`
}

// See RFC 4254, section 5.1.
const MsgChannelOpenConfirm = 91

type ChannelOpenConfirmMsg struct {
	PeersID          uint32 `sshtype:"91"`
	MyID             uint32
	MyWindow         uint32
	MaxPacketSize    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

// RejectionReason is an enumeration used when rejecting channel creation
// requests. See RFC 4254, section 5.1.
type RejectionReason uint32

const (
	Prohibited RejectionReason = iota + 1
	ConnectionFailed
	UnknownChannelType
	ResourceShortage
)

// String converts the rejection reason to human readable form.
func (r RejectionReason) String() string {
	switch r {
	case Prohibited:
		return "administratively prohibited"
	case ConnectionFailed:
		return "connect failed"
	case UnknownChannelType:
		return "unknown channel type"
	case ResourceShortage:
		return "resource shortage"
	}
	return fmt.Sprintf("unknown reason %d", int(r))
}

// See RFC 4254, section 5.1.
const MsgChannelOpenFailure = 92

type ChannelOpenFailureMsg struct {
	PeersID  uint32 `sshtype:"92"`
	Reason   RejectionReason
	Message  string
	Language string
}

const MsgChannelRequest = 98

type ChannelRequestMsg struct {
	PeersID             uint32 `sshtype:"98"`
	Request             string
	WantReply           bool
	RequestSpecificData []byte `ssh:"rest"`
}

type ChannelOpenDirectMsg struct {
	DestAddr string
	DestPort uint32
	SrcAddr  string
	SrcPort  uint32
}

type ChannelWindowChangeRequestMsg struct {
	WidthColumns uint32
	HeightRows   uint32
	WidthPx      uint32
	HeightPx     uint32
}

type ShellChannelRequestMsg struct{}

type ExecChannelRequestMsg struct {
	Command string
}

// See RFC 4254, section 5.2
const MsgChannelWindowAdjust = 93

type WindowAdjustMsg struct {
	PeersID         uint32 `sshtype:"93"`
	AdditionalBytes uint32
}

// See RFC 4254, section 5.4.
const MsgChannelSuccess = 99

type ChannelRequestSuccessMsg struct {
	PeersID uint32 `sshtype:"99"`
}

// See RFC 4254, section 5.4.
const MsgChannelFailure = 100

type ChannelRequestFailureMsg struct {
	PeersID uint32 `sshtype:"100"`
}

// See RFC 4254, section 5.3
const MsgChannelClose = 97

type ChannelCloseMsg struct {
	PeersID uint32 `sshtype:"97"`
}

// See RFC 4254, section 5.3
const MsgChannelEOF = 96

type ChannelEOFMsg struct {
	PeersID uint32 `sshtype:"96"`
}

type PtyReqChannelRequestMsg struct {
	TermEnv           string
	Width, Height     uint32
	WidthPx, HeightPx uint32
	Modes             []byte
}

// See RFC 4254, section 4
const MsgGlobalRequest = 80

type GlobalRequestMsg struct {
	Type      string `sshtype:"80"`
	WantReply bool
	Data      []byte `ssh:"rest"`
}

// See RFC 4254, section 4
const MsgRequestSuccess = 81

type GlobalRequestSuccessMsg struct {
	Data []byte `ssh:"rest" sshtype:"81"`
}

// See RFC 4254, section 4
const MsgRequestFailure = 82

type GlobalRequestFailureMsg struct {
	Data []byte `ssh:"rest" sshtype:"82"`
}

type TcpipForwardMsg struct {
	RemoteAddress string
	RemotePort    uint32
}
