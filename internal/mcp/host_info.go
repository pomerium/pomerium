package mcp

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/http"
	"net/url"
	"path"
	"sync"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

type HostInfo struct {
	cfg        *config.Config
	prefix     string
	httpClient *http.Client

	buildOnce sync.Once
	servers   map[string]ServerHostInfo
	clients   map[string]ClientHostInfo
}

type ServerHostInfo struct {
	Name        string
	Description string
	LogoURL     string
	Host        string
	URL         string
	UpstreamURL string // Actual upstream server URL (To config + server path)
	RouteID     string // Route ID from policy (needed for token storage keys)
	Config      *oauth2.Config
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
		Name:        p.Name,
		Description: p.Description,
		LogoURL:     p.LogoURL,
		Host:        u.Hostname(),
		URL:         u.String(),
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
	return &HostInfo{
		prefix:     DefaultPrefix,
		cfg:        cfg,
		httpClient: httpClient,
	}
}

func (r *HostInfo) CodeExchangeForHost(
	ctx context.Context,
	host string,
	code string,
) (*oauth2.Token, error) {
	r.buildOnce.Do(r.build)
	cfg, ok := r.servers[host]
	if !ok || cfg.Config == nil {
		return nil, fmt.Errorf("no oauth2 config for host %s", host)
	}

	return cfg.Config.Exchange(ctx, code)
}

func (r *HostInfo) IsMCPClientForHost(host string) bool {
	r.buildOnce.Do(r.build)
	_, ok := r.clients[host]
	return ok
}

func (r *HostInfo) HasOAuth2ConfigForHost(host string) bool {
	r.buildOnce.Do(r.build)
	v, ok := r.servers[host]
	return ok && v.Config != nil
}

func (r *HostInfo) GetOAuth2ConfigForHost(host string) (*oauth2.Config, bool) {
	cfg, ok := r.getConfigForHost(host)
	return cfg, ok
}

func (r *HostInfo) GetLoginURLForHost(host string, state string) (string, bool) {
	cfg, ok := r.getConfigForHost(host)
	if !ok {
		return "", false
	}

	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), true
}

func (r *HostInfo) All() iter.Seq[ServerHostInfo] {
	r.buildOnce.Do(r.build)
	return maps.Values(r.servers)
}

// UsesAutoDiscovery returns true if the host is an MCP server route
// without upstream_oauth2 configured (auto-discovery mode).
// This determines whether the host should serve a CIMD document.
func (r *HostInfo) UsesAutoDiscovery(host string) bool {
	r.buildOnce.Do(r.build)
	serverInfo, ok := r.servers[host]
	if !ok {
		return false
	}
	// Auto-discovery mode means NO upstream OAuth2 config
	return serverInfo.Config == nil
}

// GetServerHostInfo returns the ServerHostInfo for a given host.
// Returns (ServerHostInfo{}, false) if the host is not found.
func (r *HostInfo) GetServerHostInfo(host string) (ServerHostInfo, bool) {
	r.buildOnce.Do(r.build)
	info, ok := r.servers[host]
	return info, ok
}

func (r *HostInfo) getConfigForHost(host string) (*oauth2.Config, bool) {
	r.buildOnce.Do(r.build)
	if v, ok := r.servers[host]; ok && v.Config != nil {
		return v.Config, true
	}
	return nil, false
}

func (r *HostInfo) build() {
	r.servers, r.clients = BuildHostInfo(r.cfg, r.prefix)
}

// BuildHostInfo indexes all policies by host
// and builds the oauth2.Config for each host if present.
func BuildHostInfo(cfg *config.Config, prefix string) (map[string]ServerHostInfo, map[string]ClientHostInfo) {
	servers := make(map[string]ServerHostInfo)
	clients := make(map[string]ClientHostInfo)
	for policy := range cfg.Options.GetAllPolicies() {
		if policy.MCP == nil {
			continue
		}

		info, err := NewServerHostInfoFromPolicy(policy)
		if err != nil {
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
			info.Config = &oauth2.Config{
				ClientID:     oa.ClientID,
				ClientSecret: oa.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:   oa.Endpoint.AuthURL,
					TokenURL:  oa.Endpoint.TokenURL,
					AuthStyle: authStyleEnum(oa.Endpoint.AuthStyle),
				},
				RedirectURL: (&url.URL{
					Scheme: "https",
					Host:   info.Host,
					Path:   path.Join(prefix, serverOAuthCallbackEndpoint),
				}).String(),
				Scopes: oa.Scopes,
			}
		}
		servers[info.Host] = info
	}
	return servers, clients
}

func authStyleEnum(o config.OAuth2EndpointAuthStyle) oauth2.AuthStyle {
	switch o {
	case config.OAuth2EndpointAuthStyleInHeader:
		return oauth2.AuthStyleInHeader
	case config.OAuth2EndpointAuthStyleInParams:
		return oauth2.AuthStyleInParams
	default:
		return oauth2.AuthStyleAutoDetect
	}
}

func OAuth2TokenToPB(src *oauth2.Token) *oauth21proto.TokenResponse {
	r := &oauth21proto.TokenResponse{
		AccessToken:  src.AccessToken,
		TokenType:    src.TokenType,
		RefreshToken: proto.String(src.RefreshToken),
		ExpiresIn:    proto.Int64(src.ExpiresIn),
	}
	if !src.Expiry.IsZero() {
		r.ExpiresAt = timestamppb.New(src.Expiry)
	}
	return r
}

func PBToOAuth2Token(src *oauth21proto.TokenResponse) *oauth2.Token {
	token := oauth2.Token{
		AccessToken:  src.GetAccessToken(),
		TokenType:    src.GetTokenType(),
		RefreshToken: src.GetRefreshToken(),
	}
	if src.ExpiresAt != nil {
		token.Expiry = src.ExpiresAt.AsTime()
	}
	return &token
}
