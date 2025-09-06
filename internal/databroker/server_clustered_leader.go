package databroker

type clusteredLeaderServer struct {
	Server
}

// NewClusteredLeaderServer creates a new clustered leader databroker server.
// A clustered leader server implements the server interface via a local
// backend server.
func NewClusteredLeaderServer(local Server) Server {
	return &clusteredLeaderServer{local}
}
