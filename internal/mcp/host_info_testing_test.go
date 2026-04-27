package mcp

func newHostInfoForTest(servers map[string]ServerHostInfo, clients map[string]ClientHostInfo) *HostInfo {
	if servers == nil {
		servers = map[string]ServerHostInfo{}
	}
	if clients == nil {
		clients = map[string]ClientHostInfo{}
	}
	h := &HostInfo{}
	h.servers.Store(&servers)
	h.clients.Store(&clients)
	return h
}
