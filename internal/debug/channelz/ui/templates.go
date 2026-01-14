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

var dagSVGTemplate = template.Must(template.New("dag-svg").Parse(`
<svg xmlns="http://www.w3.org/2000/svg" width="{{.Width}}" height="{{.Height}}" viewBox="0 0 {{.Width}} {{.Height}}">
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#6b7280"/>
    </marker>
    <linearGradient id="state-ready" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#4ade80"/>
      <stop offset="100%" style="stop-color:#22c55e"/>
    </linearGradient>
    <linearGradient id="state-connecting" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#60a5fa"/>
      <stop offset="100%" style="stop-color:#3b82f6"/>
    </linearGradient>
    <linearGradient id="state-idle" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#9ca3af"/>
      <stop offset="100%" style="stop-color:#6b7280"/>
    </linearGradient>
    <linearGradient id="state-failure" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#f87171"/>
      <stop offset="100%" style="stop-color:#ef4444"/>
    </linearGradient>
    <linearGradient id="state-shutdown" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#a78bfa"/>
      <stop offset="100%" style="stop-color:#8b5cf6"/>
    </linearGradient>
    <linearGradient id="state-neutral" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#64748b"/>
      <stop offset="100%" style="stop-color:#475569"/>
    </linearGradient>
  </defs>

  {{range .Edges}}
  <line x1="{{.X1}}" y1="{{.Y1}}" x2="{{.X2}}" y2="{{.Y2}}" stroke="#4b5563" stroke-width="2" marker-end="url(#arrowhead)"/>
  {{end}}

  {{range .Nodes}}
  <a href="{{.DetailURL}}" target="detail-frame" data-node-url="{{.DetailURL}}">
    <g class="node" transform="translate({{.X}}, {{.Y}})" data-x="{{.X}}" data-y="{{.Y}}" data-width="{{.Width}}" data-height="{{.Height}}" style="cursor: pointer;">
      <rect class="node-rect" width="{{.Width}}" height="{{.Height}}" rx="8" ry="8" fill="url(#state-{{.StateClass}})" stroke="#1f2937" stroke-width="2"/>
      <text x="{{.TextX}}" y="20" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="600" fill="#fff">{{.TypeLabel}}</text>
      <text x="{{.TextX}}" y="36" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="10" fill="#fff">{{.Label}}</text>
      {{if .State}}<text x="{{.TextX}}" y="50" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="9" fill="rgba(255,255,255,0.8)">{{.State}}</text>{{end}}
    </g>
  </a>
  {{end}}
</svg>
`))

var dagDashboardTemplate = template.Must(template.New("dag-dashboard").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>Channelz DAG Visualization</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body {
            height: 100%;
            overflow: hidden;
        }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #111827;
            color: #f3f4f6;
            display: flex;
            flex-direction: column;
        }
        .nav-links {
            padding: 12px 24px;
            background: #1f2937;
            border-bottom: 1px solid #374151;
        }
        .nav-links a {
            color: #60a5fa;
            text-decoration: none;
            margin-right: 20px;
            font-size: 14px;
        }
        .nav-links a:hover { text-decoration: underline; }
        .summary-bar {
            padding: 16px 24px;
            background: #1f2937;
            border-bottom: 1px solid #374151;
            display: flex;
            gap: 32px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .stat { text-align: center; min-width: 70px; }
        .stat-value { font-size: 24px; font-weight: 700; }
        .stat-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; }
        .legend {
            display: flex;
            gap: 16px;
            padding: 12px 24px;
            background: #0f172a;
            border-bottom: 1px solid #374151;
            flex-wrap: wrap;
            align-items: center;
            justify-content: center;
        }
        .legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #d1d5db; }
        .legend-color { width: 14px; height: 14px; border-radius: 4px; }
        .legend-separator { width: 1px; height: 20px; background: #374151; margin: 0 8px; }
        .zoom-controls { display: flex; gap: 8px; align-items: center; }
        .zoom-btn {
            background: #374151;
            border: 1px solid #4b5563;
            color: #d1d5db;
            padding: 4px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
        }
        .zoom-btn:hover { background: #4b5563; }
        .zoom-level { font-size: 12px; color: #9ca3af; min-width: 50px; text-align: center; }
        .layout-controls { display: flex; gap: 6px; align-items: center; }
        .control-label { font-size: 12px; color: #9ca3af; margin-right: 4px; }
        .layout-btn {
            background: #374151;
            border: 1px solid #4b5563;
            color: #d1d5db;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            text-decoration: none;
        }
        .layout-btn:hover { background: #4b5563; }
        .layout-btn.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
        .container { display: flex; flex: 1; min-height: 0; }
        .dag-panel {
            flex: 1;
            overflow: hidden;
            background: #0f172a;
            position: relative;
        }
        .svg-viewport {
            width: 100%;
            height: 100%;
            cursor: grab;
            overflow: hidden;
        }
        .svg-viewport:active { cursor: grabbing; }
        .svg-viewport svg {
            transform-origin: 0 0;
        }
        .detail-panel {
            width: 480px;
            border-left: 2px solid #374151;
            display: flex;
            flex-direction: column;
            background: #1f2937;
            position: relative;
            transform: translateX(100%);
            margin-right: -480px;
            transition: transform 0.2s ease-out, margin-right 0.2s ease-out;
        }
        .detail-panel.open {
            transform: translateX(0);
            margin-right: 0;
        }
        .detail-header {
            padding: 16px;
            background: #1f2937;
            border-bottom: 1px solid #374151;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .detail-header h2 { font-size: 12px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1px; }
        .detail-header p { font-size: 13px; color: #6b7280; margin-top: 4px; }
        .close-btn {
            background: #374151;
            border: 1px solid #4b5563;
            color: #d1d5db;
            width: 28px;
            height: 28px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 18px;
            line-height: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .close-btn:hover { background: #4b5563; }
        #detail-frame {
            flex: 1;
            border: none;
            background: #1f2937;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6b7280;
        }
        .empty-state h3 { font-size: 16px; margin-bottom: 8px; color: #9ca3af; }
        /* Selected node highlight */
        .node-selected .node-rect {
            stroke: #fbbf24 !important;
            stroke-width: 4px !important;
            filter: drop-shadow(0 0 8px rgba(251, 191, 36, 0.6));
        }
        @keyframes pulse-highlight {
            0%, 100% { filter: drop-shadow(0 0 8px rgba(251, 191, 36, 0.6)); }
            50% { filter: drop-shadow(0 0 16px rgba(251, 191, 36, 0.9)); }
        }
        .node-selected .node-rect {
            animation: pulse-highlight 1.5s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <div class="nav-links">
        <a href="/channelz/">Index</a>
        <a href="/channelz/channels/">Channels Table</a>
        <a href="/channelz/servers/">Servers Table</a>
    </div>

    <div class="summary-bar">
        <div class="stat">
            <div class="stat-value" style="color: #4ade80;">{{.Stats.Ready}}</div>
            <div class="stat-label">Ready</div>
        </div>
        <div class="stat">
            <div class="stat-value" style="color: #60a5fa;">{{.Stats.Connecting}}</div>
            <div class="stat-label">Connecting</div>
        </div>
        <div class="stat">
            <div class="stat-value" style="color: #9ca3af;">{{.Stats.Idle}}</div>
            <div class="stat-label">Idle</div>
        </div>
        <div class="stat">
            <div class="stat-value" style="color: #f87171;">{{.Stats.Failed}}</div>
            <div class="stat-label">Failed</div>
        </div>
        <div class="stat">
            <div class="stat-value" style="color: #a78bfa;">{{.Stats.Shutdown}}</div>
            <div class="stat-label">Shutdown</div>
        </div>
        <div class="stat" style="border-left: 1px solid #374151; padding-left: 32px;">
            <div class="stat-value">{{.Stats.TotalChannels}}</div>
            <div class="stat-label">Channels</div>
        </div>
        <div class="stat">
            <div class="stat-value">{{.Stats.TotalSubchannels}}</div>
            <div class="stat-label">Subchannels</div>
        </div>
        <div class="stat">
            <div class="stat-value">{{.Stats.TotalSockets}}</div>
            <div class="stat-label">Sockets</div>
        </div>
        <div class="stat">
            <div class="stat-value">{{.Stats.TotalServers}}</div>
            <div class="stat-label">Servers</div>
        </div>
    </div>

    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background: linear-gradient(#4ade80, #22c55e);"></div>Ready</div>
        <div class="legend-item"><div class="legend-color" style="background: linear-gradient(#60a5fa, #3b82f6);"></div>Connecting</div>
        <div class="legend-item"><div class="legend-color" style="background: linear-gradient(#9ca3af, #6b7280);"></div>Idle</div>
        <div class="legend-item"><div class="legend-color" style="background: linear-gradient(#f87171, #ef4444);"></div>Transient Failure</div>
        <div class="legend-item"><div class="legend-color" style="background: linear-gradient(#a78bfa, #8b5cf6);"></div>Shutdown</div>
        <div class="legend-item"><div class="legend-color" style="background: linear-gradient(#64748b, #475569);"></div>Server / Socket</div>
        <div class="legend-separator"></div>
        <div class="layout-controls">
            <span class="control-label">Layout:</span>
            <a href="?layout=hierarchical" class="layout-btn{{if eq .CurrentLayout "hierarchical"}} active{{end}}">Hierarchical</a>
            <a href="?layout=hybrid" class="layout-btn{{if eq .CurrentLayout "hybrid"}} active{{end}}">Hybrid</a>
            <a href="?layout=force" class="layout-btn{{if eq .CurrentLayout "force"}} active{{end}}">Force</a>
        </div>
        <div class="legend-separator"></div>
        <div class="zoom-controls">
            <button class="zoom-btn" onclick="zoomOut()">-</button>
            <span class="zoom-level" id="zoom-level">100%</span>
            <button class="zoom-btn" onclick="zoomIn()">+</button>
            <button class="zoom-btn" onclick="resetView()">Reset</button>
        </div>
    </div>

    <div class="container">
        <div class="dag-panel">
            {{if .HasNodes}}
            <div class="svg-viewport" id="svg-viewport">
                {{.SVG}}
            </div>
            {{else}}
            <div class="empty-state">
                <h3>No channelz data available</h3>
                <p>No gRPC channels or servers are currently registered.</p>
            </div>
            {{end}}
        </div>
        <div class="detail-panel" id="detail-panel">
            <div class="detail-header">
                <div>
                    <h2>Details</h2>
                    <p id="detail-hint">Click a node to view details</p>
                </div>
                <button class="close-btn" onclick="closeDetailPanel()" title="Close">&times;</button>
            </div>
            <iframe id="detail-frame" name="detail-frame" src="about:blank"></iframe>
        </div>
    </div>

    <script>
    (function() {
        const viewport = document.getElementById('svg-viewport');
        if (!viewport) return;

        const svg = viewport.querySelector('svg');
        if (!svg) return;

        let scale = 1;
        let panX = 0;
        let panY = 0;
        let isDragging = false;
        let startX = 0;
        let startY = 0;
        let clickStartX = 0;
        let clickStartY = 0;

        const minScale = 0.1;
        const maxScale = 3;
        const zoomStep = 0.2;

        function updateTransform() {
            svg.style.transform = 'translate(' + panX + 'px, ' + panY + 'px) scale(' + scale + ')';
            document.getElementById('zoom-level').textContent = Math.round(scale * 100) + '%';
        }

        // Mouse wheel zoom
        viewport.addEventListener('wheel', function(e) {
            e.preventDefault();
            const rect = viewport.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            const oldScale = scale;
            if (e.deltaY < 0) {
                scale = Math.min(maxScale, scale * 1.1);
            } else {
                scale = Math.max(minScale, scale / 1.1);
            }

            // Zoom towards mouse position
            const scaleChange = scale / oldScale;
            panX = mouseX - (mouseX - panX) * scaleChange;
            panY = mouseY - (mouseY - panY) * scaleChange;

            updateTransform();
        }, { passive: false });

        // Pan with mouse drag
        viewport.addEventListener('mousedown', function(e) {
            if (e.button !== 0) return;
            isDragging = true;
            startX = e.clientX - panX;
            startY = e.clientY - panY;
            clickStartX = e.clientX;
            clickStartY = e.clientY;
            viewport.style.cursor = 'grabbing';
        });

        document.addEventListener('mousemove', function(e) {
            if (!isDragging) return;
            panX = e.clientX - startX;
            panY = e.clientY - startY;
            updateTransform();
        });

        document.addEventListener('mouseup', function(e) {
            if (!isDragging) return;
            isDragging = false;
            viewport.style.cursor = 'grab';

            // Detect if this was a click (minimal movement) and allow link clicks
            const dx = Math.abs(e.clientX - clickStartX);
            const dy = Math.abs(e.clientY - clickStartY);
            if (dx < 5 && dy < 5) {
                // This was a click, not a drag - let the event propagate to links
            }
        });

        // Prevent link clicks during drag and open detail panel on click
        svg.querySelectorAll('a').forEach(function(link) {
            link.addEventListener('click', function(e) {
                const dx = Math.abs(e.clientX - clickStartX);
                const dy = Math.abs(e.clientY - clickStartY);
                if (dx > 5 || dy > 5) {
                    e.preventDefault();
                } else {
                    // Open detail panel when node is clicked
                    openDetailPanel();
                    // Highlight and center the clicked node
                    const nodeUrl = link.getAttribute('data-node-url');
                    if (nodeUrl) {
                        selectNode(nodeUrl);
                    }
                }
            });
        });

        // Select and highlight a node by its URL
        function selectNode(nodeUrl) {
            // Remove previous selection
            svg.querySelectorAll('a.node-selected').forEach(function(el) {
                el.classList.remove('node-selected');
            });

            // Find and select the new node
            const nodeLink = svg.querySelector('a[data-node-url="' + nodeUrl + '"]');
            if (nodeLink) {
                nodeLink.classList.add('node-selected');
                centerOnNode(nodeLink);
            }
        }

        // Center the viewport on a node
        function centerOnNode(nodeLink) {
            const nodeGroup = nodeLink.querySelector('g.node');
            if (!nodeGroup) return;

            const nodeX = parseInt(nodeGroup.getAttribute('data-x')) || 0;
            const nodeY = parseInt(nodeGroup.getAttribute('data-y')) || 0;
            const nodeWidth = parseInt(nodeGroup.getAttribute('data-width')) || 180;
            const nodeHeight = parseInt(nodeGroup.getAttribute('data-height')) || 60;

            // Calculate center of node
            const nodeCenterX = nodeX + nodeWidth / 2;
            const nodeCenterY = nodeY + nodeHeight / 2;

            // Get viewport dimensions
            const viewportRect = viewport.getBoundingClientRect();
            const viewportCenterX = viewportRect.width / 2;
            const viewportCenterY = viewportRect.height / 2;

            // Calculate pan to center node in viewport
            panX = viewportCenterX - nodeCenterX * scale;
            panY = viewportCenterY - nodeCenterY * scale;

            updateTransform();
        }

        // Expose selectNode globally for iframe navigation
        window.selectNodeByUrl = selectNode;

        // Button controls
        window.zoomIn = function() {
            scale = Math.min(maxScale, scale + zoomStep);
            updateTransform();
        };

        window.zoomOut = function() {
            scale = Math.max(minScale, scale - zoomStep);
            updateTransform();
        };

        window.resetView = function() {
            scale = 1;
            panX = 0;
            panY = 0;
            updateTransform();
        };

        updateTransform();
    })();

    // Detail panel controls
    function openDetailPanel() {
        const panel = document.getElementById('detail-panel');
        const hint = document.getElementById('detail-hint');
        if (panel) {
            panel.classList.add('open');
        }
        if (hint) {
            hint.style.display = 'none';
        }
    }

    function closeDetailPanel() {
        const panel = document.getElementById('detail-panel');
        const frame = document.getElementById('detail-frame');
        const hint = document.getElementById('detail-hint');
        if (panel) {
            panel.classList.remove('open');
        }
        if (frame) {
            frame.src = 'about:blank';
        }
        if (hint) {
            hint.style.display = 'block';
        }
        // Clear node selection
        const svg = document.querySelector('#svg-viewport svg');
        if (svg) {
            svg.querySelectorAll('a.node-selected').forEach(function(el) {
                el.classList.remove('node-selected');
            });
        }
    }

    // Listen for iframe navigation to highlight corresponding nodes
    (function() {
        const frame = document.getElementById('detail-frame');
        if (!frame) return;

        frame.addEventListener('load', function() {
            try {
                // Get the iframe's current URL
                const frameUrl = frame.contentWindow.location.href;
                if (!frameUrl || frameUrl === 'about:blank') return;

                // Extract the path portion (e.g., /channelz/channel/123?view=card)
                const url = new URL(frameUrl);
                const pathWithQuery = url.pathname + url.search;

                // Find and highlight the matching node
                if (window.selectNodeByUrl) {
                    window.selectNodeByUrl(pathWithQuery);
                }
            } catch (e) {
                // Cross-origin or other access errors - silently ignore
            }
        });
    })();
    </script>
</body>
</html>
`))
