package mcp

import (
	"fmt"
	"iter"
	"maps"
	"net/http"
	"net/url"
	"path"
	"sync/atomic"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

type HostInfo struct {
	httpClient *http.Client

	servers atomic.Pointer[map[string]ServerHostInfo]
	clients atomic.Pointer[map[string]ClientHostInfo]
}

type ServerHostInfo struct {
	Name                   string
	Description            string
	LogoURL                string
	Host                   string
	URL                    string
	UpstreamURL            string // Actual upstream server URL (To config + server path)
	RouteID                string // Route ID from policy (needed for token storage keys)
	AuthorizationServerURL string // Fallback AS issuer URL when PRM discovery fails
	UpstreamOAuth2         *config.UpstreamOAuth2
}

func NewServerHostInfoFromPolicy(p *config.Policy) (ServerHostInfo, error) {
	u, err := url.Parse(p.GetFrom())
	if err != nil {
		return ServerHostInfo{}, fmt.Errorf("failed to parse policy FROM URL %q: %w", p.GetFrom(), err)
	}

	serverPath := p.MCP.GetServer().GetPath()
	// Only append the server path if it's not the default "/" or if the original URL already has a path
	if serverPath != "/" || u.Path != "" {
		u.Path = path.Join(u.Path, serverPath)
	}

	info := ServerHostInfo{
		Name:                   p.Name,
		Description:            p.Description,
		LogoURL:                p.LogoURL,
		Host:                   u.Hostname(),
		URL:                    u.String(),
		AuthorizationServerURL: p.MCP.GetServer().GetAuthorizationServerURL(),
	}

	// Build the actual upstream URL and route ID from the To config.
	// RouteID is derived from route-defining fields and is needed for token storage keys.
	// Both are only meaningful when To is configured (no upstream = no token storage).
	if len(p.To) > 0 {
		routeID, err := p.RouteID()
		if err != nil {
			return ServerHostInfo{}, fmt.Errorf("failed to compute route ID for policy %q: %w", p.GetFrom(), err)
		}
		info.RouteID = routeID

		toURL := p.To[0].URL
		upstreamURL := &url.URL{Scheme: toURL.Scheme, Host: toURL.Host, Path: toURL.Path}
		if serverPath != "/" || upstreamURL.Path != "" {
			upstreamURL.Path = path.Join(upstreamURL.Path, serverPath)
		}
		info.UpstreamURL = upstreamURL.String()
	}

	return info, nil
}

type ClientHostInfo struct{}

func NewHostInfo(
	cfg *config.Config,
	httpClient *http.Client,
) *HostInfo {
	h := &HostInfo{httpClient: httpClient}
	h.OnConfigChange(cfg)
	return h
}

// OnConfigChange rebuilds the host index from the given config and atomically
// swaps it in. Safe to call concurrently with readers.
func (r *HostInfo) OnConfigChange(cfg *config.Config) {
	servers, clients := BuildHostInfo(cfg)
	r.servers.Store(&servers)
	r.clients.Store(&clients)
}

func (r *HostInfo) loadServers() map[string]ServerHostInfo {
	return *r.servers.Load()
}

func (r *HostInfo) loadClients() map[string]ClientHostInfo {
	return *r.clients.Load()
}

func (r *HostInfo) IsMCPClientForHost(host string) bool {
	_, ok := r.loadClients()[host]
	return ok
}

func (r *HostInfo) All() iter.Seq[ServerHostInfo] {
	return maps.Values(r.loadServers())
}

// UsesAutoDiscovery returns true if the host is an MCP server route
// without upstream_oauth2 configured (auto-discovery mode).
// This determines whether the host should serve a CIMD document.
func (r *HostInfo) UsesAutoDiscovery(host string) bool {
	serverInfo, ok := r.loadServers()[host]
	if !ok {
		return false
	}
	// Auto-discovery mode means NO upstream OAuth2 config
	return serverInfo.UpstreamOAuth2 == nil
}

// GetServerHostInfo returns the ServerHostInfo for a given host.
// Returns (ServerHostInfo{}, false) if the host is not found.
func (r *HostInfo) GetServerHostInfo(host string) (ServerHostInfo, bool) {
	info, ok := r.loadServers()[host]
	return info, ok
}

// BuildHostInfo indexes all policies by host.
func BuildHostInfo(cfg *config.Config) (map[string]ServerHostInfo, map[string]ClientHostInfo) {
	servers := make(map[string]ServerHostInfo)
	clients := make(map[string]ClientHostInfo)
	if cfg == nil {
		return servers, clients
	}
	for policy := range cfg.Options.GetAllPolicies() {
		if policy.MCP == nil {
			continue
		}

		info, err := NewServerHostInfoFromPolicy(policy)
		if err != nil {
			log.Error().Err(err).
				Str("policy_from", policy.GetFrom()).
				Msg("mcp/host_info: skipping MCP policy due to error")
			continue
		}

		if policy.IsMCPClient() {
			clients[info.Host] = ClientHostInfo{}
			continue
		}

		if _, ok := servers[info.Host]; ok {
			continue
		}
		if oa := policy.MCP.GetServerUpstreamOAuth2(); oa != nil {
			info.UpstreamOAuth2 = oa
		}
		servers[info.Host] = info
	}
	return servers, clients
}

