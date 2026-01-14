package ui

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"

	"github.com/pomerium/pomerium/internal/debug/channelz/graph"
)

// parseIDFromPath extracts the numeric ID from a URL path with the given prefix.
func parseIDFromPath(r *http.Request, prefix string) (int64, error) {
	path := r.URL.Path
	if r.URL.RawPath != "" {
		path = r.URL.RawPath
	}
	return strconv.ParseInt(strings.TrimPrefix(path, prefix), 10, 64)
}

func (srv *Server) serveChannelZServers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
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

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := ServersTable.Render(w, resp.GetServer(), true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *Server) serveChannelZChannels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
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

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := ChannelsTable.Render(w, resp.GetChannel(), true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *Server) channelZIndexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html>
<head>
<title>Channelz</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; margin: 40px; background: #f9fafb; }
h1 { color: #111827; margin-bottom: 24px; }
.card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.card h2 { margin: 0 0 8px 0; font-size: 16px; }
.card p { margin: 0; color: #6b7280; font-size: 14px; }
.card a { color: #2563eb; text-decoration: none; }
.card a:hover { text-decoration: underline; }
.primary { border-left: 4px solid #2563eb; }
ul { list-style: none; padding: 0; margin: 16px 0 0 0; }
li { margin: 8px 0; }
</style>
</head>
<body>
<h1>Channelz Debug</h1>
<div class="card primary">
	<h2><a href="/channelz/dag">DAG Visualization</a></h2>
	<p>Interactive graph view of all gRPC channels, subchannels, sockets, and servers</p>
</div>
<div class="card">
	<h2>Table Views</h2>
	<ul>
		<li><a href="/channelz/channels/">Channels</a> - List of all top-level channels</li>
		<li><a href="/channelz/servers/">Servers</a> - List of all gRPC servers</li>
	</ul>
</div>
</body>
</html>
`)
	}
}

func (srv *Server) serveChannelZDAG() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		// Get layout type from query parameter (default: hybrid)
		layoutType := graph.LayoutType(r.URL.Query().Get("layout"))
		switch layoutType {
		case graph.LayoutHierarchical, graph.LayoutForceDirected, graph.LayoutHierarchicalForce:
			// valid
		default:
			layoutType = graph.LayoutHierarchicalForce // default to hybrid layout
		}

		graphData, stats, err := srv.collectChannelZData(r.Context(), client, layoutType)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate SVG
		var svgBuf bytes.Buffer
		svgData := struct {
			Width  int
			Height int
			Nodes  []graph.SvgNodeData
			Edges  []graph.SvgEdgeData
		}{
			Width:  graphData.Width,
			Height: graphData.Height,
			Nodes:  graphData.PrepareSVGNodes(),
			Edges:  graphData.CalculateEdgeCoordinates(),
		}

		if err := dagSVGTemplate.Execute(&svgBuf, svgData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Render full page
		pageData := struct {
			SVG           template.HTML
			Stats         *graph.DagStats
			HasNodes      bool
			CurrentLayout graph.LayoutType
		}{
			//nolint:gosec // G203: HTML is server-generated and trusted
			SVG:           template.HTML(svgBuf.String()),
			Stats:         stats,
			HasNodes:      len(graphData.Nodes) > 0,
			CurrentLayout: layoutType,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dagDashboardTemplate.Execute(w, pageData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (srv *Server) serveChannelZServer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		id, err := parseIDFromPath(r, "/channelz/server/")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp, err := client.GetServer(r.Context(), &grpc_channelz_v1.GetServerRequest{ServerId: id})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Query().Get("view") == "card" {
			row := serverFromProto(resp.GetServer(), false)
			if err := channelZServerCardTmpl.Execute(w, []serverRow{row}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else {
			if err := ServersTable.RenderOne(w, resp.GetServer(), true); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func (srv *Server) serveChannelZSubChannel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		id, err := parseIDFromPath(r, "/channelz/subchannel/")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp, err := client.GetSubchannel(r.Context(), &grpc_channelz_v1.GetSubchannelRequest{SubchannelId: id})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Query().Get("view") == "card" {
			row := subChannelFromProto(resp.GetSubchannel(), false)
			if err := channelZChannelCardTmpl.Execute(w, []channelRow{row}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else {
			if err := SubchannelsTable.RenderOne(w, resp.GetSubchannel(), true); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func (srv *Server) serveChannelZSocket() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		id, err := parseIDFromPath(r, "/channelz/socket/")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp, err := client.GetSocket(r.Context(), &grpc_channelz_v1.GetSocketRequest{SocketId: id})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Query().Get("view") == "card" {
			row := socketFromProto(resp.GetSocket())
			if err := channelZSocketCardTmpl.Execute(w, []socketRow{row}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else {
			if err := SocketsTable.RenderOne(w, resp.GetSocket(), true); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func (srv *Server) serveChannelZChannel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := srv.client.GetChannelZClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		id, err := parseIDFromPath(r, "/channelz/channel/")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp, err := client.GetChannel(r.Context(), &grpc_channelz_v1.GetChannelRequest{ChannelId: id})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Query().Get("view") == "card" {
			row := channelFromProto(resp.GetChannel(), false)
			if err := channelZChannelCardTmpl.Execute(w, []channelRow{row}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else {
			if err := ChannelsTable.RenderOne(w, resp.GetChannel(), true); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}
