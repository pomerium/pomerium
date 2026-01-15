package ui

import (
	"html/template"
	"io"
	"strings"
	"sync"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"

	"github.com/pomerium/pomerium/pkg/slices"
)

// Column defines a table column with header and field name.
type Column struct {
	Header string // Display header text
	Field  string // Template field name (e.g., ".ID", ".Name")
}

// Table combines configuration with type-safe row conversion.
type Table[Proto, Row any] struct {
	Title   string
	Columns []Column
	Convert func(proto Proto, useListWrapper bool) Row
}

// Render converts protobuf data to rows and renders the table.
func (t *Table[Proto, Row]) Render(w io.Writer, data []Proto, useListWrapper bool) error {
	rows := slices.Map(data, func(p Proto) Row {
		return t.Convert(p, useListWrapper)
	})
	tmpl := getOrBuildTemplate(t.Title, t.Columns)
	return tmpl.Execute(w, rows)
}

// RenderOne renders a single item as a table.
func (t *Table[Proto, Row]) RenderOne(w io.Writer, data Proto, useListWrapper bool) error {
	return t.Render(w, []Proto{data}, useListWrapper)
}

// Pre-configured tables for each entity type.
var (
	ChannelsTable = &Table[*grpc_channelz_v1.Channel, channelRow]{
		Title: "GRPC Channels",
		Columns: []Column{
			{Header: "ID", Field: ".ID"},
			{Header: "Name", Field: ".Name"},
			{Header: "State", Field: ".State"},
			{Header: "Target", Field: ".Target"},
			{Header: "Created At", Field: ".CreatedAt"},
			{Header: "Events", Field: ".Events"},
			{Header: "Calls Started", Field: ".CallsStarted"},
			{Header: "Calls Succeeded", Field: ".CallsSucceeded"},
			{Header: "Calls Failed", Field: ".CallsFailed"},
			{Header: "Last Call Started", Field: ".LastCallStarted"},
			{Header: "Sub-Channels", Field: ".SubChannels"},
			{Header: "Channels", Field: ".Channels"},
			{Header: "Sockets", Field: ".Sockets"},
		},
		Convert: channelFromProto,
	}

	SubchannelsTable = &Table[*grpc_channelz_v1.Subchannel, channelRow]{
		Title:   "GRPC Channels",
		Columns: ChannelsTable.Columns,
		Convert: subChannelFromProto,
	}

	ServersTable = &Table[*grpc_channelz_v1.Server, serverRow]{
		Title: "GRPC Servers",
		Columns: []Column{
			{Header: "ID", Field: ".ID"},
			{Header: "Name", Field: ".Name"},
			{Header: "Created At", Field: ".CreatedAt"},
			{Header: "Events", Field: ".Events"},
			{Header: "Calls Started", Field: ".CallsStarted"},
			{Header: "Calls Succeeded", Field: ".CallsSucceeded"},
			{Header: "Calls Failed", Field: ".CallsFailed"},
			{Header: "Last Call Started", Field: ".LastCallStarted"},
			{Header: "Listen Sockets", Field: ".ListenSocket"},
		},
		Convert: serverFromProto,
	}

	SocketsTable = &Table[*grpc_channelz_v1.Socket, socketRow]{
		Title: "GRPC Sockets",
		Columns: []Column{
			{Header: "ID", Field: ".ID"},
			{Header: "Name", Field: ".Name"},
			{Header: "Local Addr", Field: ".LocalAddr"},
			{Header: "Remote Addr", Field: ".RemoteAddr"},
			{Header: "Remote Name", Field: ".RemoteName"},
			{Header: "Security", Field: ".Security"},
			{Header: "Streams Started", Field: ".StreamsStarted"},
			{Header: "Streams Succeeded", Field: ".StreamsSucceeded"},
			{Header: "Streams Failed", Field: ".StreamsFailed"},
			{Header: "Messages Sent", Field: ".MessagesSent"},
			{Header: "Messages Received", Field: ".MessagesReceived"},
			{Header: "Keep-Alives Sent", Field: ".KeepAlivesSent"},
			{Header: "Local Flow Control", Field: ".LocalFlowControlWindow"},
			{Header: "Remote Flow Control", Field: ".RemoteFlowControlWindow"},
		},
		Convert: func(s *grpc_channelz_v1.Socket, _ bool) socketRow {
			return socketFromProto(s)
		},
	}
)

// tableCSS contains the shared styles for all tables.
const tableCSS = `* { box-sizing: border-box; margin: 0; padding: 0; }
body {
	font-family: system-ui, -apple-system, sans-serif;
	background: #111827;
	color: #f3f4f6;
	padding: 24px;
}
h1 {
	font-size: 20px;
	font-weight: 600;
	margin-bottom: 16px;
	color: #f3f4f6;
}
.nav {
	margin-bottom: 16px;
}
.nav a {
	color: #60a5fa;
	text-decoration: none;
	margin-right: 16px;
	font-size: 14px;
}
.nav a:hover { text-decoration: underline; }
.table-container {
	overflow-x: auto;
	border-radius: 8px;
	border: 1px solid #374151;
}
table {
	width: 100%;
	border-collapse: collapse;
	font-size: 13px;
}
th {
	background: #1f2937;
	color: #9ca3af;
	font-weight: 600;
	text-transform: uppercase;
	font-size: 11px;
	letter-spacing: 0.5px;
	padding: 12px 16px;
	text-align: left;
	border-bottom: 1px solid #374151;
	white-space: nowrap;
}
td {
	padding: 12px 16px;
	border-bottom: 1px solid #374151;
	color: #e5e7eb;
	vertical-align: top;
}
tr:hover td {
	background: #1f2937;
}
td a {
	color: #60a5fa;
	text-decoration: none;
}
td a:hover { text-decoration: underline; }
ul {
	list-style: none;
	padding: 0;
	margin: 0;
}
li { margin: 4px 0; }
details summary {
	cursor: pointer;
	color: #60a5fa;
}
details table {
	margin-top: 8px;
	font-size: 12px;
}
details th, details td {
	padding: 6px 10px;
}`

// templateCache stores compiled templates to avoid recompilation.
var (
	templateCache   = make(map[string]*template.Template)
	templateCacheMu sync.RWMutex
)

// getOrBuildTemplate returns a cached template or builds and caches a new one.
func getOrBuildTemplate(title string, columns []Column) *template.Template {
	templateCacheMu.RLock()
	if tmpl, ok := templateCache[title]; ok {
		templateCacheMu.RUnlock()
		return tmpl
	}
	templateCacheMu.RUnlock()

	templateCacheMu.Lock()
	defer templateCacheMu.Unlock()

	// Double-check after acquiring write lock
	if tmpl, ok := templateCache[title]; ok {
		return tmpl
	}

	tmpl := buildTableTemplate(title, columns)
	templateCache[title] = tmpl
	return tmpl
}

// buildTableTemplate creates a template specific to the config.
func buildTableTemplate(title string, columns []Column) *template.Template {
	var headerCells, dataCells strings.Builder

	for _, col := range columns {
		headerCells.WriteString("<th>")
		headerCells.WriteString(col.Header)
		headerCells.WriteString("</th>")

		dataCells.WriteString("<td>{{")
		dataCells.WriteString(col.Field)
		dataCells.WriteString("}}</td>")
	}

	var tmplStr strings.Builder
	tmplStr.WriteString(`<!DOCTYPE html>
<html>
<head>
<title>`)
	tmplStr.WriteString(title)
	tmplStr.WriteString(`</title>
<style>`)
	tmplStr.WriteString(tableCSS)
	tmplStr.WriteString(`</style>
</head>
<body>
<div class="nav">
	<a href="/channelz/">Index</a>
	<a href="/channelz/channels/">Channels</a>
	<a href="/channelz/servers/">Servers</a>
</div>
<h1>`)
	tmplStr.WriteString(title)
	tmplStr.WriteString(`</h1>
<div class="table-container">
<table>
<thead>
<tr>`)
	tmplStr.WriteString(headerCells.String())
	tmplStr.WriteString(`</tr>
</thead>
<tbody>
{{range .}}
<tr>`)
	tmplStr.WriteString(dataCells.String())
	tmplStr.WriteString(`</tr>
{{end}}
</tbody>
</table>
</div>
</body>
</html>`)

	return template.Must(template.New("table").Parse(tmplStr.String()))
}
