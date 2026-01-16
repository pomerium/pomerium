package ui

import (
	"fmt"
	"html/template"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/slices"
)

// channelRow represents a channel or subchannel for table/card rendering.
type channelRow struct {
	ID              int64
	Name            string
	Type            string
	State           string
	Target          string
	CreatedAt       string
	Events          template.HTML
	CallsStarted    int64
	CallsSucceeded  int64
	CallsFailed     int64
	LastCallStarted string
	SubChannels     template.HTML
	Channels        template.HTML
	Sockets         template.HTML
}

// socketRow represents a socket for table/card rendering.
type socketRow struct {
	ID                      int64
	Name                    string
	LocalAddr               string
	RemoteAddr              string
	RemoteName              string
	Security                string
	StreamsStarted          int64
	StreamsSucceeded        int64
	StreamsFailed           int64
	MessagesSent            int64
	MessagesReceived        int64
	KeepAlivesSent          int64
	LastLocalStreamCreated  string
	LastRemoteStreamCreated string
	LastMessageSent         string
	LastMessageReceived     string
	LocalFlowControlWindow  string
	RemoteFlowControlWindow string
}

// serverRow represents a server for table/card rendering.
type serverRow struct {
	ID              int64
	Name            string
	ListenSocket    template.HTML
	CreatedAt       string
	Events          template.HTML
	CallsStarted    int64
	CallsSucceeded  int64
	CallsFailed     int64
	LastCallStarted string
}

// channelFromProto converts a protobuf Channel to a channelRow.
func channelFromProto(ch *grpc_channelz_v1.Channel, useListWrapper bool) channelRow {
	d := ch.GetData()
	listFn := listItemsHTML
	if useListWrapper {
		listFn = listHTML
	}
	return channelRow{
		ID:              ch.GetRef().GetChannelId(),
		Name:            ch.GetRef().GetName(),
		Type:            "Channel",
		State:           d.GetState().GetState().String(),
		Target:          d.GetTarget(),
		CreatedAt:       formatTime(d.GetTrace().GetCreationTimestamp().AsTime()),
		Events:          eventsHTML(d.GetTrace()),
		CallsStarted:    d.GetCallsStarted(),
		CallsSucceeded:  d.GetCallsSucceeded(),
		CallsFailed:     d.GetCallsFailed(),
		LastCallStarted: formatTime(d.GetLastCallStartedTimestamp().AsTime()),
		SubChannels:     listFn(slices.Map(ch.GetSubchannelRef(), subchannelRefLink)),
		Channels:        listFn(slices.Map(ch.GetChannelRef(), channelRefLink)),
		Sockets:         listFn(slices.Map(ch.GetSocketRef(), socketRefLink)),
	}
}

// subChannelFromProto converts a protobuf Subchannel to a channelRow.
func subChannelFromProto(ch *grpc_channelz_v1.Subchannel, useListWrapper bool) channelRow {
	d := ch.GetData()
	listFn := listItemsHTML
	if useListWrapper {
		listFn = listHTML
	}
	return channelRow{
		ID:              ch.GetRef().GetSubchannelId(),
		Name:            ch.GetRef().GetName(),
		Type:            "Subchannel",
		State:           d.GetState().GetState().String(),
		Target:          d.GetTarget(),
		CreatedAt:       formatTime(d.GetTrace().GetCreationTimestamp().AsTime()),
		Events:          eventsHTML(d.GetTrace()),
		CallsStarted:    d.GetCallsStarted(),
		CallsSucceeded:  d.GetCallsSucceeded(),
		CallsFailed:     d.GetCallsFailed(),
		LastCallStarted: formatTime(d.GetLastCallStartedTimestamp().AsTime()),
		SubChannels:     listFn(slices.Map(ch.GetSubchannelRef(), subchannelRefLink)),
		Channels:        listFn(slices.Map(ch.GetChannelRef(), channelRefLink)),
		Sockets:         listFn(slices.Map(ch.GetSocketRef(), socketRefLink)),
	}
}

// serverFromProto converts a protobuf Server to a serverRow.
func serverFromProto(s *grpc_channelz_v1.Server, useListWrapper bool) serverRow {
	d := s.GetData()
	listFn := listItemsHTML
	if useListWrapper {
		listFn = listHTML
	}
	return serverRow{
		ID:              s.GetRef().GetServerId(),
		Name:            s.GetRef().GetName(),
		ListenSocket:    listFn(slices.Map(s.GetListenSocket(), socketRefLink)),
		CreatedAt:       formatTime(d.GetTrace().GetCreationTimestamp().AsTime()),
		Events:          eventsHTML(d.GetTrace()),
		CallsStarted:    d.GetCallsStarted(),
		CallsSucceeded:  d.GetCallsSucceeded(),
		CallsFailed:     d.GetCallsFailed(),
		LastCallStarted: formatTime(d.GetLastCallStartedTimestamp().AsTime()),
	}
}

// socketFromProto converts a protobuf Socket to a socketRow.
func socketFromProto(sock *grpc_channelz_v1.Socket) socketRow {
	data := sock.GetData()
	return socketRow{
		ID:                      sock.GetRef().GetSocketId(),
		Name:                    sock.GetRef().GetName(),
		LocalAddr:               formatAddress(sock.GetLocal()),
		RemoteAddr:              formatAddress(sock.GetRemote()),
		RemoteName:              sock.GetRemoteName(),
		Security:                sock.GetSecurity().String(),
		StreamsStarted:          data.GetStreamsStarted(),
		StreamsSucceeded:        data.GetStreamsSucceeded(),
		StreamsFailed:           data.GetStreamsFailed(),
		MessagesSent:            data.GetMessagesSent(),
		MessagesReceived:        data.GetMessagesReceived(),
		KeepAlivesSent:          data.GetKeepAlivesSent(),
		LastLocalStreamCreated:  formatTime(data.GetLastLocalStreamCreatedTimestamp().AsTime()),
		LastRemoteStreamCreated: formatTime(data.GetLastRemoteStreamCreatedTimestamp().AsTime()),
		LastMessageSent:         formatTime(data.GetLastMessageSentTimestamp().AsTime()),
		LastMessageReceived:     formatTime(data.GetLastMessageReceivedTimestamp().AsTime()),
		LocalFlowControlWindow:  formatFlowControlWindow(data.GetLocalFlowControlWindow()),
		RemoteFlowControlWindow: formatFlowControlWindow(data.GetRemoteFlowControlWindow()),
	}
}

// formatTime formats a time value for display.
func formatTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

// formatAddress formats a channelz Address into a human-readable string.
func formatAddress(addr *grpc_channelz_v1.Address) string {
	if addr == nil {
		return "-"
	}
	switch a := addr.GetAddress().(type) {
	case *grpc_channelz_v1.Address_TcpipAddress:
		if a.TcpipAddress == nil {
			return "-"
		}
		ip := net.IP(a.TcpipAddress.GetIpAddress())
		port := a.TcpipAddress.GetPort()
		if ip.To4() != nil {
			return fmt.Sprintf("%s:%d", ip, port)
		}
		return fmt.Sprintf("[%s]:%d", ip, port)
	case *grpc_channelz_v1.Address_UdsAddress_:
		if a.UdsAddress == nil {
			return "-"
		}
		return "unix://" + a.UdsAddress.GetFilename()
	case *grpc_channelz_v1.Address_OtherAddress_:
		if a.OtherAddress == nil {
			return "-"
		}
		if name := a.OtherAddress.GetName(); name != "" {
			return name
		}
		return "other"
	default:
		return "-"
	}
}

// formatFlowControlWindow formats a flow control window value.
func formatFlowControlWindow(fcw *wrapperspb.Int64Value) string {
	if fcw == nil {
		return "-"
	}
	return strconv.FormatInt(fcw.GetValue(), 10)
}

// refLink generates an HTML link for a channelz reference.
func refLink(path string, id int64, name string) string {
	label := strconv.FormatInt(id, 10)
	if name != "" {
		label = fmt.Sprintf("%d | %s", id, name)
	}
	return fmt.Sprintf(`<a href="/channelz/%s/%d?view=card">%s</a>`, path, id, label)
}

func channelRefLink(ref *grpc_channelz_v1.ChannelRef) string {
	return refLink("channel", ref.GetChannelId(), ref.GetName())
}

func subchannelRefLink(ref *grpc_channelz_v1.SubchannelRef) string {
	return refLink("subchannel", ref.GetSubchannelId(), ref.GetName())
}

func socketRefLink(ref *grpc_channelz_v1.SocketRef) string {
	return refLink("socket", ref.GetSocketId(), ref.GetName())
}

// listHTML wraps items in a <ul> list.
//
//nolint:gosec // G203: HTML is server-generated and trusted
func listHTML(items []string) template.HTML {
	var sb strings.Builder
	sb.WriteString("<ul>")
	for _, item := range items {
		sb.WriteString("<li>")
		sb.WriteString(item)
		sb.WriteString("</li>")
	}
	sb.WriteString("</ul>")
	return template.HTML(sb.String())
}

// listItemsHTML returns just the <li> items without the <ul> wrapper (for card templates).
//
//nolint:gosec // G203: HTML is server-generated and trusted
func listItemsHTML(items []string) template.HTML {
	var sb strings.Builder
	for _, item := range items {
		sb.WriteString("<li>")
		sb.WriteString(item)
		sb.WriteString("</li>")
	}
	return template.HTML(sb.String())
}

// eventsHTML renders a channel trace as an expandable details element.
//
//nolint:gosec // G203: HTML is server-generated and trusted
func eventsHTML(trace *grpc_channelz_v1.ChannelTrace) template.HTML {
	var sb strings.Builder
	sb.WriteString(`<details><summary>details (`)
	sb.WriteString(strconv.FormatInt(trace.GetNumEventsLogged(), 10))
	sb.WriteString(`)</summary><table><tr><th>Timestamp</th><th>Severity</th><th>Description</th></tr>`)
	for _, event := range trace.GetEvents() {
		if event == nil {
			continue
		}
		sb.WriteString("<tr><td>")
		sb.WriteString(formatTime(event.GetTimestamp().AsTime()))
		sb.WriteString("</td><td>")
		sb.WriteString(event.GetSeverity().String())
		sb.WriteString("</td><td>")
		sb.WriteString(event.GetDescription())
		sb.WriteString("</td></tr>")
	}
	sb.WriteString("</table></details>")
	return template.HTML(sb.String())
}
