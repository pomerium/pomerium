package controlplane

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"

	slicesutil "github.com/pomerium/pomerium/pkg/slices"
)

var (
	channelZChannelsTmpl = template.Must(template.New("channels").Parse(`
<html>
<head>
<title>GRPC channels</title>
<style>
table { font-family: arial, sans-serif; border-collapse: collapse; width: 100%; }
td, th { border: 1px solid #dddddd; text-align: left; padding: 8px; }
tr:nth-child(even) { background-color: #dddddd; }
</style>
</head>
<body>
<table>
<tr>
	<th>channel ID</th>
	<th>name</th>
	<th>state</th>
	<th>target</th>
	<th>created at</th>
	<th>events</th>
	<th>calls started</th>
	<th>calls succeeded</th>
	<th>calls failed</th>
	<th>last call started</th>
	<th>sub-channels</th>
	<th>channels</th>
	<th>sockets</th>
</tr>
{{range .}}
<tr>
	<td>{{.ID}}</td>
	<td>{{.Name}}</td>
	<td>{{.State}}</td>
	<td>{{.Target}}</td>
	<td>{{.CreatedAt}}</td>
	<td>{{.Events}}</td>
	<td>{{.CallsStarted}}</td>
	<td>{{.CallsSucceeded}}</td>
	<td>{{.CallsFailed}}</td>
	<td>{{.LastCallStarted}}</td>
	<td>{{.SubChannels}}</td>
	<td>{{.Channels}}</td>
	<td>{{.Sockets}}</td>
</tr>
{{end}}
</table>
</body>
</html>`))
	channelZServersTmpl = template.Must(template.New("servers").Parse(`
<html>
<head>
<title>GRPC servers</title>
<style>
table { font-family: arial, sans-serif; border-collapse: collapse; width: 100%; }
td, th { border: 1px solid #dddddd; text-align: left; padding: 8px; }
tr:nth-child(even) { background-color: #dddddd; }
</style>
</head>
<body>
<table>
<tr>
	<th>server ID</th>
	<th>name</th>
	<th>created at</th>
	<th>events</th>
	<th>calls started</th>
	<th>calls succeeded</th>
	<th>calls failed</th>
	<th>last call started</th>
	<th>sockets</th>
</tr>
{{range .}}
<tr>
	<td>{{.ID}}</td>
	<td>{{.Name}}</td>
	<td>{{.CreatedAt}}</td>
	<td>{{.Events}}</td>
	<td>{{.CallsStarted}}</td>
	<td>{{.CallsSucceeded}}</td>
	<td>{{.CallsFailed}}</td>
	<td>{{.LastCallStarted}}</td>
	<td>{{.ListenSocket}}</td>
</tr>
{{end}}
</table>
</body>
</html>`))
	channelZSocketTmpl = template.Must(template.New("sockets").Parse(`
<html>
<head>
<title>GRPC sockets</title>
<style>
table { font-family: arial, sans-serif; border-collapse: collapse; width: 100%; }
td, th { border: 1px solid #dddddd; text-align: left; padding: 8px; }
tr:nth-child(even) { background-color: #dddddd; }
</style>
</head>
<body>
<table>
<tr>
	<th>socket ID</th>
	<th>name</th>
	<th>local addr</th>
	<th>remote addr</th>
	<th>remote name</th>
	<th>security</th>
</tr>
{{range .}}
<tr>
	<td>{{.ID}}</td>
	<td>{{.Name}}</td>
	<td>{{.LocalAddr}}</td>
	<td>{{.RemoteAddr}}</td>
	<td>{{.RemoteName}}</td>
	<td>{{.Security}}</td>
</tr>
{{end}}
</table>
</body>
</html>`))
)

type channelRow struct {
	ID              int64
	Name            string
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

type socketRow struct {
	ID         int64
	Name       string
	LocalAddr  string
	RemoteAddr string
	RemoteName string
	Security   string
}

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

func renderTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

func (srv *debugServer) setupChannelZClient() (grpc_channelz_v1.ChannelzClient, error) {
	clientPtr := srv.channelZClient.Load()
	if clientPtr == nil || *clientPtr == nil {
		return nil, fmt.Errorf("grpc admin client(s) not available")
	}

	client := (*clientPtr).GetLocalChannelZClient()
	if client == nil {
		return nil, fmt.Errorf("channelz client not available")
	}
	return client, nil
}

func (srv *debugServer) channelZIndexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html>
<head>
<title>Channelz options</title>
</head>
<body>
		<ul>
			<li><a href="/channelz/channels"> Channels </a></li>
			<li><a href="/channelz/servers"> Servers </li>
		</ul>
</body>
`)
	}
}

func (srv *debugServer) serveChannelZServers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.setupChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		resp, err := client.GetServers(r.Context(),
			&grpc_channelz_v1.GetServersRequest{
				StartServerId: 0,
				MaxResults:    100,
			})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var rows []serverRow
		for _, srv := range resp.GetServer() {
			d := srv.GetData()
			rows = append(rows, serverRow{
				ID:   srv.GetRef().GetServerId(),
				Name: srv.GetRef().GetName(),
				//nolint:gosec // G203: HTML is server-generated and trusted
				ListenSocket: template.HTML(writeList(
					slicesutil.Map(srv.GetListenSocket(), func(ref *grpc_channelz_v1.SocketRef) string {
						return renderSocketRef(ref)
					}),
				)),
				CreatedAt: renderTime(d.GetTrace().GetCreationTimestamp().AsTime()),
				//nolint:gosec // G203: HTML is server-generated and trusted
				Events:          template.HTML(renderEvents(d.GetTrace())),
				CallsStarted:    d.GetCallsStarted(),
				CallsSucceeded:  d.GetCallsSucceeded(),
				CallsFailed:     d.GetCallsFailed(),
				LastCallStarted: renderTime(d.GetLastCallStartedTimestamp().AsTime()),
			})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := channelZServersTmpl.Execute(w, rows); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *debugServer) serveChannelZChannel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.setupChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		path := r.URL.Path
		if r.URL.RawPath != "" {
			path = r.URL.RawPath
		}
		id := strings.TrimPrefix(path, "/channelz/channel/")
		idN, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := client.GetChannel(r.Context(),
			&grpc_channelz_v1.GetChannelRequest{
				ChannelId: idN,
			})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var rows []channelRow
		ch := resp.Channel
		d := ch.GetData()
		rows = append(rows, channelRow{
			ID:        ch.GetRef().GetChannelId(),
			Name:      ch.GetRef().GetName(),
			State:     d.GetState().String(),
			Target:    d.GetTarget(),
			CreatedAt: renderTime(d.GetTrace().GetCreationTimestamp().AsTime()),
			//nolint:gosec // G203: HTML is server-generated and trusted
			Events:          template.HTML(renderEvents(d.GetTrace())),
			CallsStarted:    d.GetCallsStarted(),
			CallsSucceeded:  d.GetCallsSucceeded(),
			CallsFailed:     d.GetCallsFailed(),
			LastCallStarted: renderTime(d.GetLastCallStartedTimestamp().AsTime()),
			//nolint:gosec // G203: HTML is server-generated and trusted
			SubChannels: template.HTML(writeList(
				slicesutil.Map(ch.GetSubchannelRef(), renderSubChannelRef),
			)),
			//nolint:gosec // G203: HTML is server-generated and trusted
			Channels: template.HTML(writeList(
				slicesutil.Map(ch.GetChannelRef(), renderChannelRef),
			)),
			//nolint:gosec // G203: HTML is server-generated and trusted
			Sockets: template.HTML(writeList(
				slicesutil.Map(ch.GetSocketRef(), renderSocketRef),
			)),
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := channelZChannelsTmpl.Execute(w, rows); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *debugServer) serveChannelZSubChannel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.setupChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		path := r.URL.Path
		if r.URL.RawPath != "" {
			path = r.URL.RawPath
		}
		id := strings.TrimPrefix(path, "/channelz/subchannel/")
		idN, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := client.GetSubchannel(r.Context(),
			&grpc_channelz_v1.GetSubchannelRequest{
				SubchannelId: idN,
			})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var rows []channelRow
		ch := resp.Subchannel
		d := ch.GetData()
		rows = append(rows, channelRow{
			ID:        ch.GetRef().GetSubchannelId(),
			Name:      ch.GetRef().GetName(),
			State:     d.GetState().String(),
			Target:    d.GetTarget(),
			CreatedAt: renderTime(d.GetTrace().GetCreationTimestamp().AsTime()),
			//nolint:gosec // G203: HTML is server-generated and trusted
			Events:          template.HTML(renderEvents(d.GetTrace())),
			CallsStarted:    d.GetCallsStarted(),
			CallsSucceeded:  d.GetCallsSucceeded(),
			CallsFailed:     d.GetCallsFailed(),
			LastCallStarted: renderTime(d.GetLastCallStartedTimestamp().AsTime()),
			//nolint:gosec // G203: HTML is server-generated and trusted
			SubChannels: template.HTML(writeList(
				slicesutil.Map(ch.GetSubchannelRef(), renderSubChannelRef),
			)),
			//nolint:gosec // G203: HTML is server-generated and trusted
			Channels: template.HTML(writeList(
				slicesutil.Map(ch.GetChannelRef(), renderChannelRef),
			)),
			//nolint:gosec // G203: HTML is server-generated and trusted
			Sockets: template.HTML(writeList(
				slicesutil.Map(ch.GetSocketRef(), renderSocketRef),
			)),
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := channelZChannelsTmpl.Execute(w, rows); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *debugServer) serveChannelZSocket() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.setupChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		path := r.URL.Path
		if r.URL.RawPath != "" {
			path = r.URL.RawPath
		}
		id := strings.TrimPrefix(path, "/channelz/socket/")
		idN, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp, err := client.GetSocket(r.Context(),
			&grpc_channelz_v1.GetSocketRequest{
				SocketId: idN,
			})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sock := resp.GetSocket()
		rows := []socketRow{
			{
				ID:         sock.Ref.GetSocketId(),
				Name:       sock.GetRef().GetName(),
				LocalAddr:  sock.GetLocal().String(),
				RemoteAddr: sock.GetRemote().String(),
				RemoteName: sock.GetRemoteName(),
				Security:   sock.GetSecurity().String(),
			},
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := channelZSocketTmpl.Execute(w, rows); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *debugServer) serveChannelZChannels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.setupChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		resp, err := client.GetTopChannels(r.Context(),
			&grpc_channelz_v1.GetTopChannelsRequest{
				StartChannelId: 0,
				MaxResults:     100,
			})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var rows []channelRow
		for _, ch := range resp.GetChannel() {
			d := ch.GetData()
			rows = append(rows, channelRow{
				ID:        ch.GetRef().GetChannelId(),
				Name:      ch.GetRef().GetName(),
				State:     d.GetState().String(),
				Target:    d.GetTarget(),
				CreatedAt: renderTime(d.GetTrace().GetCreationTimestamp().AsTime()),
				//nolint:gosec // G203: HTML is server-generated and trusted
				Events:          template.HTML(renderEvents(d.GetTrace())),
				CallsStarted:    d.GetCallsStarted(),
				CallsSucceeded:  d.GetCallsSucceeded(),
				CallsFailed:     d.GetCallsFailed(),
				LastCallStarted: renderTime(d.GetLastCallStartedTimestamp().AsTime()),
				//nolint:gosec // G203: HTML is server-generated and trusted
				SubChannels: template.HTML(writeList(
					slicesutil.Map(ch.GetSubchannelRef(), renderSubChannelRef),
				)),
				//nolint:gosec // G203: HTML is server-generated and trusted
				Channels: template.HTML(writeList(
					slicesutil.Map(ch.GetChannelRef(), renderChannelRef),
				)),
				//nolint:gosec // G203: HTML is server-generated and trusted
				Sockets: template.HTML(writeList(
					slicesutil.Map(ch.GetSocketRef(), renderSocketRef),
				)),
			})
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := channelZChannelsTmpl.Execute(w, rows); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func renderEvents(trace *grpc_channelz_v1.ChannelTrace) string {
	tableContents := strings.Builder{}
	for _, event := range trace.GetEvents() {
		tableContents.WriteString(renderEvent(event))
	}
	return fmt.Sprintf(`<details>
		<summary>
			details (%d)
		</summary>
		<table>
			<tr>
				<th> Timestamp </th>
				<th> Severity </th>
				<th> Description </th>
			</tr>
			%s
		</table>
	</details>
	`, trace.GetNumEventsLogged(), tableContents.String())
}

func renderEvent(event *grpc_channelz_v1.ChannelTraceEvent) string {
	if event == nil {
		return ""
	}
	sb := strings.Builder{}
	sb.WriteString("<tr>")
	sb.WriteString(writeCell(renderTime(event.GetTimestamp().AsTime())))
	// TODO : child ref
	sb.WriteString(writeCell(event.GetSeverity().String()))
	sb.WriteString(writeCell(event.GetDescription()))
	sb.WriteString("</tr>")
	return sb.String()
}

func renderChannelRef(ref *grpc_channelz_v1.ChannelRef) string {
	var name string
	if ref.GetName() != "" {
		name = fmt.Sprintf("%d | %s", ref.GetChannelId(), ref.GetName())
	} else {
		name = fmt.Sprintf("%d", ref.GetChannelId())
	}
	return fmt.Sprintf(`<a href="/channelz/channel/%d"> %s </a>`, ref.GetChannelId(), name)
}

func renderSubChannelRef(ref *grpc_channelz_v1.SubchannelRef) string {
	var name string
	if ref.GetName() != "" {
		name = fmt.Sprintf("%d | %s", ref.GetSubchannelId(), ref.GetName())
	} else {
		name = fmt.Sprintf("%d", ref.GetSubchannelId())
	}
	return fmt.Sprintf(`<a href="/channelz/subchannel/%d"> %s </a>`, ref.GetSubchannelId(), name)
}

func renderSocketRef(ref *grpc_channelz_v1.SocketRef) string {
	var name string
	if ref.GetName() != "" {
		name = fmt.Sprintf("%d | %s", ref.GetSocketId(), ref.GetName())
	} else {
		name = fmt.Sprintf("%d", ref.GetSocketId())
	}
	return fmt.Sprintf(`<a href="/channelz/socket/%d"> %s </a>`, ref.GetSocketId(), name)
}

func writeList(items []string) string {
	sb := strings.Builder{}
	sb.WriteString("<ul>")
	for _, item := range items {
		sb.WriteString("<li>")
		sb.WriteString(item)
		sb.WriteString("</li>")
	}
	sb.WriteString("</ul>")
	return sb.String()
}

func writeCell(content string) string {
	return fmt.Sprintf("<td> %s </td>", content)
}
