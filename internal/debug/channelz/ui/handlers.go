package ui

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"
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
</head>
<body>
<h1>Channelz Debug</h1>
<div>
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
