package databroker

import "github.com/pomerium/pomerium/pkg/health"

type clusteredLeaderServer struct {
	Server
}

// NewClusteredLeaderServer creates a new clustered leader databroker server.
// A clustered leader server implements the server interface via a local
// backend server.
func NewClusteredLeaderServer(local Server) Server {
	health.ReportRunning(health.DatabrokerCluster, health.StrAttr("member", "leader"))
	return &clusteredLeaderServer{local}
}

func (srv *clusteredLeaderServer) Stop() {}
