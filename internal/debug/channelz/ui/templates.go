package ui

import "html/template"

var (
	channelZChannelCardTmpl = template.Must(template.New("channel-card").Parse(`<!DOCTYPE html>
<html>
<head>
<title>Channel Details</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
	font-family: system-ui, -apple-system, sans-serif;
	background: #1f2937;
	color: #f3f4f6;
	padding: 16px;
	font-size: 13px;
}
.card {
	background: #111827;
	border-radius: 8px;
	padding: 16px;
	margin-bottom: 12px;
}
.card-header {
	display: flex;
	align-items: center;
	gap: 12px;
	margin-bottom: 12px;
	padding-bottom: 12px;
	border-bottom: 1px solid #374151;
}
.type-badge {
	background: #3b82f6;
	color: #fff;
	padding: 4px 10px;
	border-radius: 4px;
	font-size: 11px;
	font-weight: 600;
	text-transform: uppercase;
}
.state-badge {
	padding: 4px 10px;
	border-radius: 4px;
	font-size: 11px;
	font-weight: 600;
}
.state-READY { background: #22c55e; color: #fff; }
.state-CONNECTING { background: #3b82f6; color: #fff; }
.state-IDLE { background: #6b7280; color: #fff; }
.state-TRANSIENT_FAILURE { background: #ef4444; color: #fff; }
.state-SHUTDOWN { background: #8b5cf6; color: #fff; }
h1 {
	font-size: 16px;
	font-weight: 600;
	word-break: break-all;
}
.field {
	margin-bottom: 10px;
}
.field-label {
	font-size: 11px;
	color: #9ca3af;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	margin-bottom: 2px;
}
.field-value {
	color: #e5e7eb;
	word-break: break-all;
}
.field-value.mono {
	font-family: ui-monospace, monospace;
	font-size: 12px;
	background: #374151;
	padding: 4px 8px;
	border-radius: 4px;
}
.stats-grid {
	display: grid;
	grid-template-columns: repeat(3, 1fr);
	gap: 12px;
	margin-bottom: 12px;
}
.stat-box {
	background: #374151;
	border-radius: 6px;
	padding: 10px;
	text-align: center;
}
.stat-value {
	font-size: 20px;
	font-weight: 700;
	color: #fff;
}
.stat-value.success { color: #4ade80; }
.stat-value.error { color: #f87171; }
.stat-label {
	font-size: 10px;
	color: #9ca3af;
	text-transform: uppercase;
}
.section-title {
	font-size: 12px;
	font-weight: 600;
	color: #9ca3af;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	margin: 16px 0 8px 0;
}
.link-list {
	list-style: none;
}
.link-list li {
	margin-bottom: 6px;
}
.link-list a {
	color: #60a5fa;
	text-decoration: none;
	font-size: 12px;
}
.link-list a:hover {
	text-decoration: underline;
}
details {
	margin-top: 12px;
}
summary {
	cursor: pointer;
	color: #60a5fa;
	font-size: 12px;
	padding: 8px 0;
}
details table {
	width: 100%;
	border-collapse: collapse;
	margin-top: 8px;
	font-size: 11px;
}
details th, details td {
	border: 1px solid #374151;
	padding: 6px 8px;
	text-align: left;
}
details th {
	background: #374151;
	color: #d1d5db;
}
details td {
	color: #e5e7eb;
}
</style>
</head>
<body>
{{range .}}
<div class="card">
	<div class="card-header">
		<span class="type-badge">{{.Type}}</span>
		{{if .State}}<span class="state-badge state-{{.State}}">{{.State}}</span>{{end}}
	</div>
	<h1>{{if .Name}}{{.Name}}{{else}}ID: {{.ID}}{{end}}</h1>
</div>

<div class="card">
	<div class="field">
		<div class="field-label">ID</div>
		<div class="field-value mono">{{.ID}}</div>
	</div>
	{{if .Target}}
	<div class="field">
		<div class="field-label">Target</div>
		<div class="field-value mono">{{.Target}}</div>
	</div>
	{{end}}
	<div class="field">
		<div class="field-label">Created At</div>
		<div class="field-value">{{.CreatedAt}}</div>
	</div>
	<div class="field">
		<div class="field-label">Last Call Started</div>
		<div class="field-value">{{.LastCallStarted}}</div>
	</div>
</div>

<div class="card">
	<div class="stats-grid">
		<div class="stat-box">
			<div class="stat-value">{{.CallsStarted}}</div>
			<div class="stat-label">Started</div>
		</div>
		<div class="stat-box">
			<div class="stat-value success">{{.CallsSucceeded}}</div>
			<div class="stat-label">Succeeded</div>
		</div>
		<div class="stat-box">
			<div class="stat-value error">{{.CallsFailed}}</div>
			<div class="stat-label">Failed</div>
		</div>
	</div>
	{{.Events}}
</div>

{{if or .SubChannels .Channels .Sockets}}
<div class="card">
	{{if .SubChannels}}
	<div class="section-title">Sub-Channels</div>
	<ul class="link-list">{{.SubChannels}}</ul>
	{{end}}
	{{if .Channels}}
	<div class="section-title">Child Channels</div>
	<ul class="link-list">{{.Channels}}</ul>
	{{end}}
	{{if .Sockets}}
	<div class="section-title">Sockets</div>
	<ul class="link-list">{{.Sockets}}</ul>
	{{end}}
</div>
{{end}}
{{end}}
</body>
</html>`))
	channelZSocketCardTmpl = template.Must(template.New("socket-card").Parse(`<!DOCTYPE html>
<html>
<head>
<title>Socket Details</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
	font-family: system-ui, -apple-system, sans-serif;
	background: #1f2937;
	color: #f3f4f6;
	padding: 16px;
	font-size: 13px;
}
.card {
	background: #111827;
	border-radius: 8px;
	padding: 16px;
	margin-bottom: 12px;
}
.card-header {
	display: flex;
	align-items: center;
	gap: 12px;
	margin-bottom: 12px;
	padding-bottom: 12px;
	border-bottom: 1px solid #374151;
}
.type-badge {
	background: #64748b;
	color: #fff;
	padding: 4px 10px;
	border-radius: 4px;
	font-size: 11px;
	font-weight: 600;
	text-transform: uppercase;
}
h1 {
	font-size: 16px;
	font-weight: 600;
	word-break: break-all;
}
.field {
	margin-bottom: 10px;
}
.field-label {
	font-size: 11px;
	color: #9ca3af;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	margin-bottom: 2px;
}
.field-value {
	color: #e5e7eb;
	word-break: break-all;
}
.field-value.mono {
	font-family: ui-monospace, monospace;
	font-size: 12px;
	background: #374151;
	padding: 4px 8px;
	border-radius: 4px;
	display: inline-block;
}
.stats-grid {
	display: grid;
	grid-template-columns: repeat(3, 1fr);
	gap: 12px;
	margin-bottom: 12px;
}
.stat-box {
	background: #374151;
	border-radius: 6px;
	padding: 10px;
	text-align: center;
}
.stat-value {
	font-size: 20px;
	font-weight: 700;
	color: #fff;
}
.stat-value.success { color: #4ade80; }
.stat-value.error { color: #f87171; }
.stat-label {
	font-size: 10px;
	color: #9ca3af;
	text-transform: uppercase;
}
.section-title {
	font-size: 12px;
	font-weight: 600;
	color: #9ca3af;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	margin: 16px 0 8px 0;
}
.two-col {
	display: grid;
	grid-template-columns: 1fr 1fr;
	gap: 12px;
}
</style>
</head>
<body>
{{range .}}
<div class="card">
	<div class="card-header">
		<span class="type-badge">Socket</span>
	</div>
	<h1>{{if .Name}}{{.Name}}{{else}}Socket {{.ID}}{{end}}</h1>
</div>

<div class="card">
	<div class="field">
		<div class="field-label">ID</div>
		<div class="field-value mono">{{.ID}}</div>
	</div>
	{{if .LocalAddr}}
	<div class="field">
		<div class="field-label">Local Address</div>
		<div class="field-value mono">{{.LocalAddr}}</div>
	</div>
	{{end}}
	{{if .RemoteAddr}}
	<div class="field">
		<div class="field-label">Remote Address</div>
		<div class="field-value mono">{{.RemoteAddr}}</div>
	</div>
	{{end}}
	{{if .RemoteName}}
	<div class="field">
		<div class="field-label">Remote Name</div>
		<div class="field-value">{{.RemoteName}}</div>
	</div>
	{{end}}
	{{if .Security}}
	<div class="field">
		<div class="field-label">Security</div>
		<div class="field-value">{{.Security}}</div>
	</div>
	{{end}}
</div>

<div class="card">
	<div class="section-title">Stream Statistics</div>
	<div class="stats-grid">
		<div class="stat-box">
			<div class="stat-value">{{.StreamsStarted}}</div>
			<div class="stat-label">Started</div>
		</div>
		<div class="stat-box">
			<div class="stat-value success">{{.StreamsSucceeded}}</div>
			<div class="stat-label">Succeeded</div>
		</div>
		<div class="stat-box">
			<div class="stat-value error">{{.StreamsFailed}}</div>
			<div class="stat-label">Failed</div>
		</div>
	</div>
	<div class="section-title">Message Statistics</div>
	<div class="stats-grid">
		<div class="stat-box">
			<div class="stat-value">{{.MessagesSent}}</div>
			<div class="stat-label">Sent</div>
		</div>
		<div class="stat-box">
			<div class="stat-value">{{.MessagesReceived}}</div>
			<div class="stat-label">Received</div>
		</div>
		<div class="stat-box">
			<div class="stat-value">{{.KeepAlivesSent}}</div>
			<div class="stat-label">Keep-Alives</div>
		</div>
	</div>
</div>

<div class="card">
	<div class="section-title">Flow Control Windows</div>
	<div class="two-col">
		<div class="field">
			<div class="field-label">Local Window</div>
			<div class="field-value mono">{{.LocalFlowControlWindow}}</div>
		</div>
		<div class="field">
			<div class="field-label">Remote Window</div>
			<div class="field-value mono">{{.RemoteFlowControlWindow}}</div>
		</div>
	</div>
</div>

<div class="card">
	<div class="section-title">Timestamps</div>
	<div class="two-col">
		<div class="field">
			<div class="field-label">Last Local Stream Created</div>
			<div class="field-value">{{.LastLocalStreamCreated}}</div>
		</div>
		<div class="field">
			<div class="field-label">Last Remote Stream Created</div>
			<div class="field-value">{{.LastRemoteStreamCreated}}</div>
		</div>
	</div>
	<div class="two-col">
		<div class="field">
			<div class="field-label">Last Message Sent</div>
			<div class="field-value">{{.LastMessageSent}}</div>
		</div>
		<div class="field">
			<div class="field-label">Last Message Received</div>
			<div class="field-value">{{.LastMessageReceived}}</div>
		</div>
	</div>
</div>
{{end}}
</body>
</html>`))
	channelZServerCardTmpl = template.Must(template.New("server-card").Parse(`<!DOCTYPE html>
<html>
<head>
<title>Server Details</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
	font-family: system-ui, -apple-system, sans-serif;
	background: #1f2937;
	color: #f3f4f6;
	padding: 16px;
	font-size: 13px;
}
.card {
	background: #111827;
	border-radius: 8px;
	padding: 16px;
	margin-bottom: 12px;
}
.card-header {
	display: flex;
	align-items: center;
	gap: 12px;
	margin-bottom: 12px;
	padding-bottom: 12px;
	border-bottom: 1px solid #374151;
}
.type-badge {
	background: #64748b;
	color: #fff;
	padding: 4px 10px;
	border-radius: 4px;
	font-size: 11px;
	font-weight: 600;
	text-transform: uppercase;
}
h1 {
	font-size: 16px;
	font-weight: 600;
	word-break: break-all;
}
.field {
	margin-bottom: 10px;
}
.field-label {
	font-size: 11px;
	color: #9ca3af;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	margin-bottom: 2px;
}
.field-value {
	color: #e5e7eb;
	word-break: break-all;
}
.field-value.mono {
	font-family: ui-monospace, monospace;
	font-size: 12px;
	background: #374151;
	padding: 4px 8px;
	border-radius: 4px;
}
.stats-grid {
	display: grid;
	grid-template-columns: repeat(3, 1fr);
	gap: 12px;
	margin-bottom: 12px;
}
.stat-box {
	background: #374151;
	border-radius: 6px;
	padding: 10px;
	text-align: center;
}
.stat-value {
	font-size: 20px;
	font-weight: 700;
	color: #fff;
}
.stat-value.success { color: #4ade80; }
.stat-value.error { color: #f87171; }
.stat-label {
	font-size: 10px;
	color: #9ca3af;
	text-transform: uppercase;
}
.section-title {
	font-size: 12px;
	font-weight: 600;
	color: #9ca3af;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	margin: 16px 0 8px 0;
}
.link-list {
	list-style: none;
}
.link-list li {
	margin-bottom: 6px;
}
.link-list a {
	color: #60a5fa;
	text-decoration: none;
	font-size: 12px;
}
.link-list a:hover {
	text-decoration: underline;
}
details {
	margin-top: 12px;
}
summary {
	cursor: pointer;
	color: #60a5fa;
	font-size: 12px;
	padding: 8px 0;
}
details table {
	width: 100%;
	border-collapse: collapse;
	margin-top: 8px;
	font-size: 11px;
}
details th, details td {
	border: 1px solid #374151;
	padding: 6px 8px;
	text-align: left;
}
details th {
	background: #374151;
	color: #d1d5db;
}
details td {
	color: #e5e7eb;
}
</style>
</head>
<body>
{{range .}}
<div class="card">
	<div class="card-header">
		<span class="type-badge">Server</span>
	</div>
	<h1>{{if .Name}}{{.Name}}{{else}}Server {{.ID}}{{end}}</h1>
</div>

<div class="card">
	<div class="field">
		<div class="field-label">ID</div>
		<div class="field-value mono">{{.ID}}</div>
	</div>
	<div class="field">
		<div class="field-label">Created At</div>
		<div class="field-value">{{.CreatedAt}}</div>
	</div>
	<div class="field">
		<div class="field-label">Last Call Started</div>
		<div class="field-value">{{.LastCallStarted}}</div>
	</div>
</div>

<div class="card">
	<div class="stats-grid">
		<div class="stat-box">
			<div class="stat-value">{{.CallsStarted}}</div>
			<div class="stat-label">Started</div>
		</div>
		<div class="stat-box">
			<div class="stat-value success">{{.CallsSucceeded}}</div>
			<div class="stat-label">Succeeded</div>
		</div>
		<div class="stat-box">
			<div class="stat-value error">{{.CallsFailed}}</div>
			<div class="stat-label">Failed</div>
		</div>
	</div>
	{{.Events}}
</div>

{{if .ListenSocket}}
<div class="card">
	<div class="section-title">Listen Sockets</div>
	<ul class="link-list">{{.ListenSocket}}</ul>
</div>
{{end}}
{{end}}
</body>
</html>`))
)
