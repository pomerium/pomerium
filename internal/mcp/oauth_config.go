package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
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

func (r *OAuth2Configs) CodeExchangeForHost(
	ctx context.Context,
	host string,
	code string,
) (*oauth2.Token, error) {
	r.buildOnce.Do(r.build)
	cfg, ok := r.perHost[host]
	if !ok {
		return nil, fmt.Errorf("no oauth2 config for host %s", host)
	}

	return cfg.Exchange(ctx, code)
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

func OAuth2TokenToPB(src *oauth2.Token) *oauth21proto.TokenResponse {
	return &oauth21proto.TokenResponse{
		AccessToken:  src.AccessToken,
		TokenType:    src.TokenType,
		RefreshToken: proto.String(src.RefreshToken),
		ExpiresIn:    proto.Int64(src.ExpiresIn),
	}
}

func PBToOAuth2Token(src *oauth21proto.TokenResponse, now time.Time) oauth2.Token {
	token := oauth2.Token{
		AccessToken:  src.GetAccessToken(),
		TokenType:    src.GetTokenType(),
		ExpiresIn:    src.GetExpiresIn(),
		RefreshToken: src.GetRefreshToken(),
	}
	if token.ExpiresIn > 0 {
		token.Expiry = now.Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return token
}
