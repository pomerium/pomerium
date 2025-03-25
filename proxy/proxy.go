// Package proxy is a pomerium service that provides reverse proxying of
// internal routes. The proxy packages interoperates with other pomerium
// services over RPC in order to make access control decisions about a
// given incoming request.
package proxy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/handlers/webauthn"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	"github.com/pomerium/pomerium/proxy/portal"
)

const (
	// authenticate urls
	dashboardPath = "/.pomerium"
	signinURL     = "/.pomerium/sign_in"
	refreshURL    = "/.pomerium/refresh"
)

// ValidateOptions checks that proper configuration settings are set to create
// a proper Proxy instance
func ValidateOptions(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("proxy: invalid 'SHARED_SECRET': %w", err)
	}

	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("proxy: invalid 'SHARED_SECRET': %w", err)
	}

	cookieSecret, err := o.GetCookieSecret()
	if err != nil {
		return fmt.Errorf("proxy: invalid 'COOKIE_SECRET': %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(cookieSecret); err != nil {
		return fmt.Errorf("proxy: invalid 'COOKIE_SECRET': %w", err)
	}

	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	state          *atomicutil.Value[*proxyState]
	currentConfig  *atomicutil.Value[*config.Config]
	currentRouter  *atomicutil.Value[*mux.Router]
	webauthn       *webauthn.Handler
	tracerProvider oteltrace.TracerProvider
	logoProvider   portal.LogoProvider
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(ctx context.Context, cfg *config.Config) (*Proxy, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "Proxy")
	state, err := newProxyStateFromConfig(ctx, tracerProvider, cfg)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		tracerProvider: tracerProvider,
		state:          atomicutil.NewValue(state),
		currentConfig:  atomicutil.NewValue(&config.Config{Options: config.NewDefaultOptions()}),
		currentRouter:  atomicutil.NewValue(httputil.NewRouter()),
		logoProvider:   portal.NewLogoProvider(),
	}
	p.OnConfigChange(ctx, cfg)
	p.webauthn = webauthn.New(p.getWebauthnState)

	metrics.AddPolicyCountCallback("pomerium-proxy", func() int64 {
		return int64(p.currentConfig.Load().Options.NumPolicies())
	})

	return p, nil
}

// Mount mounts the http handler to a mux router.
func (p *Proxy) Mount(r *mux.Router) {
	r.PathPrefix("/").Handler(p)
}

// OnConfigChange updates internal structures based on config.Options
func (p *Proxy) OnConfigChange(ctx context.Context, cfg *config.Config) {
	if p == nil {
		return
	}

	p.currentConfig.Store(cfg)
	if err := p.setHandlers(ctx, cfg.Options); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("proxy: failed to update proxy handlers from configuration settings")
	}
	if state, err := newProxyStateFromConfig(ctx, p.tracerProvider, cfg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("proxy: failed to update proxy state from configuration settings")
	} else {
		p.state.Store(state)
	}
}

func (p *Proxy) setHandlers(ctx context.Context, opts *config.Options) error {
	if opts.NumPolicies() == 0 {
		log.Ctx(ctx).Info().Msg("proxy: configuration has no policies")
	}
	r := httputil.NewRouter()
	r.NotFoundHandler = httputil.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		return httputil.NewError(http.StatusNotFound, fmt.Errorf("%s route unknown", r.Host))
	})
	r.SkipClean(true)
	r.StrictSlash(true)
	// dashboard handlers are registered to all routes
	r = p.registerDashboardHandlers(r, opts)
	// attach the querier to the context
	r.Use(p.querierMiddleware)
	r.Use(trace.NewHTTPMiddleware(otelhttp.WithTracerProvider(p.tracerProvider)))

	p.currentRouter.Store(r)
	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.currentRouter.Load().ServeHTTP(w, r)
}

func (p *Proxy) querierMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = storage.WithQuerier(ctx, storage.NewCachingQuerier(
			storage.NewQuerier(p.state.Load().dataBrokerClient),
			storage.GlobalCache,
		))
		r = r.WithContext(ctx)

		h.ServeHTTP(w, r)
	})
}
