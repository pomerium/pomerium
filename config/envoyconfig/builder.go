package envoyconfig

import (
	"context"
	"net/url"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// A Builder builds envoy config from pomerium config.
type Builder struct {
	staticBuilderConfig
}

type staticBuilderConfig struct {
	localGRPCAddress    string
	localHTTPAddress    string
	localMetricsAddress string
	filemgr             *filemgr.Manager
	reproxy             *reproxy.Handler
}

type ScopedBuilder struct {
	*staticBuilderConfig
	cfg *config.Config

	staticHttpRoutes             []*envoy_config_route_v3.Route
	staticAuthenticateHttpRoutes []*envoy_config_route_v3.Route

	authenticateURL         *url.URL
	internalAuthenticateURL *url.URL
	authorizeURLs           []*url.URL
	internalAuthorizeURLs   []*url.URL
	dataBrokerURLs          []*url.URL
	internalDataBrokerURLs  []*url.URL

	domainsForWellKnownURLs map[*url.URL][]string
}

func (b *ScopedBuilder) computeStaticObjects(ctx context.Context) error {
	b.staticHttpRoutes = []*envoy_config_route_v3.Route{
		b.buildControlPlanePathRoute(ctx, "/ping"),
		b.buildControlPlanePathRoute(ctx, "/healthz"),
		b.buildControlPlanePathRoute(ctx, "/.pomerium"),
		b.buildControlPlanePrefixRoute(ctx, "/.pomerium/"),
		b.buildControlPlanePathRoute(ctx, "/.well-known/pomerium"),
		b.buildControlPlanePrefixRoute(ctx, "/.well-known/pomerium/"),
	}
	b.staticAuthenticateHttpRoutes = []*envoy_config_route_v3.Route{
		b.buildControlPlanePathRoute(ctx, b.cfg.Options.AuthenticateCallbackPath),
		b.buildControlPlanePathRoute(ctx, "/"),
		b.buildControlPlanePathRoute(ctx, "/robots.txt"),
	}
	var err error
	b.authenticateURL, err = b.cfg.Options.GetAuthenticateURL()
	if err != nil {
		return err
	}
	b.internalAuthenticateURL, err = b.cfg.Options.GetInternalAuthenticateURL()
	if err != nil {
		return err
	}
	b.authorizeURLs, err = b.cfg.Options.GetAuthorizeURLs()
	if err != nil {
		return err
	}
	b.internalAuthorizeURLs, err = b.cfg.Options.GetInternalAuthorizeURLs()
	if err != nil {
		return err
	}
	b.dataBrokerURLs, err = b.cfg.Options.GetDataBrokerURLs()
	if err != nil {
		return err
	}
	b.internalDataBrokerURLs, err = b.cfg.Options.GetInternalDataBrokerURLs()
	if err != nil {
		return err
	}

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
	return nil
}

func (b *Builder) WithConfig(cfg *config.Config) *ScopedBuilder {
	if cfg.Options == nil {
		cfg.Options = &config.Options{}
	}
	sb := &ScopedBuilder{
		staticBuilderConfig: &b.staticBuilderConfig,
		cfg:                 cfg,
	}
	sb.computeStaticObjects(context.TODO())
	return sb
}

// New creates a new Builder.
func New(
	localGRPCAddress string,
	localHTTPAddress string,
	localMetricsAddress string,
	fileManager *filemgr.Manager,
	reproxyHandler *reproxy.Handler,
) *Builder {
	if reproxyHandler == nil {
		reproxyHandler = reproxy.New()
	}
	return &Builder{
		staticBuilderConfig: staticBuilderConfig{
			localGRPCAddress:    localGRPCAddress,
			localHTTPAddress:    localHTTPAddress,
			localMetricsAddress: localMetricsAddress,
			filemgr:             fileManager,
			reproxy:             reproxyHandler,
		},
	}
}
