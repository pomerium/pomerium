package ui

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"

	"github.com/pomerium/pomerium/internal/debug/channelz/graph"
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
	mux.HandleFunc(fmt.Sprintf("GET /%s/dag", prefix), srv.serveChannelZDAG())
	mux.HandleFunc(fmt.Sprintf("GET /%s/channels/", prefix), srv.serveChannelZChannels())
	mux.HandleFunc(fmt.Sprintf("GET /%s/servers/", prefix), srv.serveChannelZServers())
	mux.HandleFunc(fmt.Sprintf("GET /%s/server/", prefix), srv.serveChannelZServer())
	mux.HandleFunc(fmt.Sprintf("GET /%s/subchannel/", prefix), srv.serveChannelZSubChannel())
	mux.HandleFunc(fmt.Sprintf("GET /%s/socket/", prefix), srv.serveChannelZSocket())
	mux.HandleFunc(fmt.Sprintf("GET /%s/channel/", prefix), srv.serveChannelZChannel())
}

// collectChannelZData fetches all channelz data and builds the DAG
func (srv *Server) collectChannelZData(ctx context.Context, client grpc_channelz_v1.ChannelzClient, layoutType graph.LayoutType) (*graph.DagGraph, *graph.DagStats, error) {
	data, err := srv.fetchChannelZData(ctx, client)
	if err != nil {
		return nil, nil, err
	}

	graphData, stats := graph.FromChannelZData(data)

	// Apply the selected layout algorithm
	layout := graph.GetLayoutAlgorithm(layoutType)
	graphData.ApplyLayout(layout)

	return graphData, stats, nil
}

// fetchChannelZData fetches all channelz data from the gRPC server
func (srv *Server) fetchChannelZData(ctx context.Context, client grpc_channelz_v1.ChannelzClient) (*graph.ChannelZData, error) {
	data := graph.NewChannelZData()

	// Get top channels
	topChannels, err := client.GetTopChannels(ctx, &grpc_channelz_v1.GetTopChannelsRequest{
		StartChannelId: 0,
		MaxResults:     100,
	})
	if err != nil {
		return nil, fmt.Errorf("GetTopChannels: %w", err)
	}
	data.TopChannels = topChannels.GetChannel()

	// Recursively fetch all channels and subchannels
	for _, ch := range data.TopChannels {
		if err := srv.fetchChannelRecursive(ctx, client, data, ch); err != nil {
			return nil, err
		}
	}

	// Get servers
	servers, err := client.GetServers(ctx, &grpc_channelz_v1.GetServersRequest{
		StartServerId: 0,
		MaxResults:    100,
	})
	if err != nil {
		return nil, fmt.Errorf("GetServers: %w", err)
	}
	data.Servers = servers.GetServer()

	return data, nil
}

func (srv *Server) fetchChannelRecursive(ctx context.Context, client grpc_channelz_v1.ChannelzClient, data *graph.ChannelZData, ch *grpc_channelz_v1.Channel) error {
	channelID := ch.GetRef().GetChannelId()

	// Skip if already fetched
	if _, exists := data.Channels[channelID]; exists {
		return nil
	}
	data.Channels[channelID] = ch

	// Fetch subchannels
	for _, subRef := range ch.GetSubchannelRef() {
		if err := srv.fetchSubchannelRecursive(ctx, client, data, subRef.GetSubchannelId()); err != nil {
			return err
		}
	}

	// Fetch child channels
	for _, chRef := range ch.GetChannelRef() {
		childCh, err := client.GetChannel(ctx, &grpc_channelz_v1.GetChannelRequest{
			ChannelId: chRef.GetChannelId(),
		})
		if err != nil {
			continue // Skip on error
		}
		if childCh.GetChannel() != nil {
			if err := srv.fetchChannelRecursive(ctx, client, data, childCh.GetChannel()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (srv *Server) fetchSubchannelRecursive(ctx context.Context, client grpc_channelz_v1.ChannelzClient, data *graph.ChannelZData, subchannelID int64) error {
	// Skip if already fetched
	if _, exists := data.Subchannels[subchannelID]; exists {
		return nil
	}

	sub, err := client.GetSubchannel(ctx, &grpc_channelz_v1.GetSubchannelRequest{
		SubchannelId: subchannelID,
	})
	if err != nil {
		return nil // Skip on error
	}

	subchannel := sub.GetSubchannel()
	if subchannel == nil {
		return nil
	}

	data.Subchannels[subchannelID] = subchannel

	// Fetch nested subchannels
	for _, subRef := range subchannel.GetSubchannelRef() {
		if err := srv.fetchSubchannelRecursive(ctx, client, data, subRef.GetSubchannelId()); err != nil {
			return err
		}
	}
	return nil
}
