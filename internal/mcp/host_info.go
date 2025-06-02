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

type OAuth2Configs struct {
	cfg        *config.Config
	prefix     string
	httpClient *http.Client

	buildOnce sync.Once
	perHost   map[string]HostInfo
}

type HostInfo struct {
	Name        string
	Description string
	LogoURL     string
	Host        string
	URL         string
	Config      *oauth2.Config
}

func NewOAuthConfig(
	cfg *config.Config,
	httpClient *http.Client,
) *OAuth2Configs {
	return &OAuth2Configs{
		prefix:     DefaultPrefix,
		cfg:        cfg,
		httpClient: httpClient,
	}
}

func (r *OAuth2Configs) CodeExchangeForHost(
	ctx context.Context,
	host string,
	code string,
) (*oauth2.Token, error) {
	r.buildOnce.Do(r.build)
	cfg, ok := r.perHost[host]
	if !ok || cfg.Config == nil {
		return nil, fmt.Errorf("no oauth2 config for host %s", host)
	}

	return cfg.Config.Exchange(ctx, code)
}

func (r *OAuth2Configs) HasOAuth2ConfigForHost(host string) bool {
	r.buildOnce.Do(r.build)
	v, ok := r.perHost[host]
	return ok && v.Config != nil
}

func (r *OAuth2Configs) GetOAuth2ConfigForHost(host string) (*oauth2.Config, bool) {
	cfg, ok := r.getConfigForHost(host)
	return cfg, ok
}

func (r *OAuth2Configs) GetLoginURLForHost(host string, state string) (string, bool) {
	cfg, ok := r.getConfigForHost(host)
	if !ok {
		return "", false
	}

	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), true
}

func (r *OAuth2Configs) All() iter.Seq[HostInfo] {
	r.buildOnce.Do(r.build)
	return maps.Values(r.perHost)
}

func (r *OAuth2Configs) getConfigForHost(host string) (*oauth2.Config, bool) {
	r.buildOnce.Do(r.build)
	if v, ok := r.perHost[host]; ok && v.Config != nil {
		return v.Config, true
	}
	return nil, false
}

func (r *OAuth2Configs) build() {
	r.perHost = BuildHostInfo(r.cfg, r.prefix)
}

// BuildHostInfo indexes all policies by host
// and builds the oauth2.Config for each host if present.
func BuildHostInfo(cfg *config.Config, prefix string) map[string]HostInfo {
	info := make(map[string]HostInfo)
	for policy := range cfg.Options.GetAllPolicies() {
		if !policy.IsMCPServer() {
			continue
		}
		u, err := url.Parse(policy.GetFrom())
		if err != nil {
			continue
		}
		host := u.Hostname()
		if _, ok := info[host]; ok {
			continue
		}
		v := HostInfo{
			Name:        policy.Name,
			Description: policy.Description,
			LogoURL:     policy.LogoURL,
			Host:        host,
			URL:         policy.GetFrom(),
		}
		if policy.MCP.UpstreamOAuth2 != nil {
			v.Config = &oauth2.Config{
				ClientID:     policy.MCP.UpstreamOAuth2.ClientID,
				ClientSecret: policy.MCP.UpstreamOAuth2.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:   policy.MCP.UpstreamOAuth2.Endpoint.AuthURL,
					TokenURL:  policy.MCP.UpstreamOAuth2.Endpoint.TokenURL,
					AuthStyle: authStyleEnum(policy.MCP.UpstreamOAuth2.Endpoint.AuthStyle),
				},
				RedirectURL: (&url.URL{
					Scheme: "https",
					Host:   host,
					Path:   path.Join(prefix, oauthCallbackEndpoint),
				}).String(),
				Scopes: policy.MCP.UpstreamOAuth2.Scopes,
			}
		}
		info[host] = v
	}
	return info
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
