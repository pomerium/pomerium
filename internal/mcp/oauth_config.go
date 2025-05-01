package mcp

import (
	"net/http"
	"net/url"
	"path"
	"sync"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/config"
)

type OAuth2Configs struct {
	cfg        *config.Config
	prefix     string
	httpClient *http.Client

	buildOnce sync.Once
	perHost   map[string]*oauth2.Config
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

func (r *OAuth2Configs) GetLoginURLForHost(host string, state string) (string, bool) {
	r.buildOnce.Do(r.build)

	cfg, ok := r.perHost[host]
	if !ok {
		return "", false
	}

	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), true
}

func (r *OAuth2Configs) build() {
	r.perHost = BuildOAuthConfig(r.cfg, r.prefix)
}

// BuildOAuthConfig builds a map of OAuth2 configs per host
func BuildOAuthConfig(cfg *config.Config, prefix string) map[string]*oauth2.Config {
	configs := make(map[string]*oauth2.Config)
	for policy := range cfg.Options.GetAllPolicies() {
		if !policy.IsMCPServer() || policy.MCP.UpstreamOAuth2 == nil {
			continue
		}
		u, err := url.Parse(policy.GetFrom())
		if err != nil {
			continue
		}
		host := u.Hostname()
		if _, ok := configs[host]; ok {
			continue
		}
		cfg := &oauth2.Config{
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
		configs[host] = cfg
	}
	return configs
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
