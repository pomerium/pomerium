package envoyconfig

import (
	"net/url"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// A BuilderOptions builds envoy config from pomerium config.
type BuilderOptions struct {
	LocalGRPCAddress    string
	LocalHTTPAddress    string
	LocalMetricsAddress string
	FileManager         *filemgr.Manager
	ReproxyHandler      *reproxy.Handler
}

type Builder struct {
	opts BuilderOptions
	cfg  *config.Config

	staticHTTPRoutes             []*envoy_config_route_v3.Route
	staticAuthenticateHTTPRoutes []*envoy_config_route_v3.Route

	authenticateURL         *url.URL
	internalAuthenticateURL *url.URL
	authorizeURLs           []*url.URL
	internalAuthorizeURLs   []*url.URL
	dataBrokerURLs          []*url.URL
	internalDataBrokerURLs  []*url.URL

	domainsForWellKnownURLs map[*url.URL][]string
}

func (b *Builder) computeWellKnownFields() {
	b.staticHTTPRoutes = []*envoy_config_route_v3.Route{
		b.buildControlPlanePathRoute("/ping"),
		b.buildControlPlanePathRoute("/healthz"),
		b.buildControlPlanePathRoute("/.pomerium"),
		b.buildControlPlanePrefixRoute("/.pomerium/"),
		b.buildControlPlanePathRoute("/.well-known/pomerium"),
		b.buildControlPlanePrefixRoute("/.well-known/pomerium/"),
	}
	b.staticAuthenticateHTTPRoutes = []*envoy_config_route_v3.Route{
		b.buildControlPlanePathRoute(b.cfg.Options.AuthenticateCallbackPath),
		b.buildControlPlanePathRoute("/"),
		b.buildControlPlanePathRoute("/robots.txt"),
	}
	b.authenticateURL, _ = b.cfg.Options.GetAuthenticateURL()
	b.internalAuthenticateURL, _ = b.cfg.Options.GetInternalAuthenticateURL()
	b.authorizeURLs, _ = b.cfg.Options.GetAuthorizeURLs()
	b.internalAuthorizeURLs, _ = b.cfg.Options.GetInternalAuthorizeURLs()
	b.dataBrokerURLs, _ = b.cfg.Options.GetDataBrokerURLs()
	b.internalDataBrokerURLs, _ = b.cfg.Options.GetInternalDataBrokerURLs()

	b.domainsForWellKnownURLs = map[*url.URL][]string{
		b.authenticateURL:         urlutil.GetDomainsForURL(b.authenticateURL, true),
		b.internalAuthenticateURL: urlutil.GetDomainsForURL(b.internalAuthenticateURL, true),
	}
	for _, u := range b.authorizeURLs {
		b.domainsForWellKnownURLs[u] = urlutil.GetDomainsForURL(u, true)
	}
	for _, u := range b.internalAuthorizeURLs {
		b.domainsForWellKnownURLs[u] = urlutil.GetDomainsForURL(u, true)
	}
	for _, u := range b.dataBrokerURLs {
		b.domainsForWellKnownURLs[u] = urlutil.GetDomainsForURL(u, true)
	}
	for _, u := range b.internalDataBrokerURLs {
		b.domainsForWellKnownURLs[u] = urlutil.GetDomainsForURL(u, true)
	}
}

func (b BuilderOptions) NewForConfig(cfg *config.Config) *Builder {
	if cfg.Options == nil {
		cfg.Options = &config.Options{}
	}
	if b.ReproxyHandler == nil {
		b.ReproxyHandler = reproxy.New()
	}
	sb := &Builder{
		opts: b,
		cfg:  cfg,
	}
	sb.computeWellKnownFields()
	return sb
}

// NewOptions creates a new BuilderOptions.
func NewOptions(
	localGRPCAddress string,
	localHTTPAddress string,
	localMetricsAddress string,
	fileManager *filemgr.Manager,
	reproxyHandler *reproxy.Handler,
) BuilderOptions {
	return BuilderOptions{
		LocalGRPCAddress:    localGRPCAddress,
		LocalHTTPAddress:    localHTTPAddress,
		LocalMetricsAddress: localMetricsAddress,
		FileManager:         fileManager,
		ReproxyHandler:      reproxyHandler,
	}
}
