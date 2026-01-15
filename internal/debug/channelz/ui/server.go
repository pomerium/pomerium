package ui

import (
	"fmt"
	"net/http"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"
)

type ClientProvider interface {
	GetChannelZClient() (grpc_channelz_v1.ChannelzClient, error)
}

type Server struct {
	client ClientProvider
}

func NewServer(client ClientProvider) *Server {
	return &Server{
		client: client,
	}
}

func (srv *Server) Register(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(fmt.Sprintf("GET /%s/", prefix), srv.channelZIndexHandler())
	mux.HandleFunc(fmt.Sprintf("GET /%s/channels/", prefix), srv.serveChannelZChannels())
	mux.HandleFunc(fmt.Sprintf("GET /%s/servers/", prefix), srv.serveChannelZServers())
	mux.HandleFunc(fmt.Sprintf("GET /%s/server/", prefix), srv.serveChannelZServer())
	mux.HandleFunc(fmt.Sprintf("GET /%s/subchannel/", prefix), srv.serveChannelZSubChannel())
	mux.HandleFunc(fmt.Sprintf("GET /%s/socket/", prefix), srv.serveChannelZSocket())
	mux.HandleFunc(fmt.Sprintf("GET /%s/channel/", prefix), srv.serveChannelZChannel())
}
