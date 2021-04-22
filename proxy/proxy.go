// Package proxy is a pomerium service that provides reverse proxying of
// internal routes. The proxy packages interoperates with other pomerium
// services over RPC in order to make access control decisions about a
// given incoming request.
package proxy

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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

	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("proxy: invalid 'COOKIE_SECRET': %w", err)
	}

	if _, err := o.GetAuthenticateURL(); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}

	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	templates      *template.Template
	state          *atomicProxyState
	currentOptions *config.AtomicOptions
	currentRouter  atomic.Value
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(cfg *config.Config) (*Proxy, error) {
	state, err := newProxyStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		templates:      template.Must(frontend.NewTemplates()),
		state:          newAtomicProxyState(state),
		currentOptions: config.NewAtomicOptions(),
	}
	p.currentRouter.Store(httputil.NewRouter())

	metrics.AddPolicyCountCallback("pomerium-proxy", func() int64 {
		return int64(len(p.currentOptions.Load().GetAllPolicies()))
	})

	return p, nil
}

// OnConfigChange updates internal structures based on config.Options
func (p *Proxy) OnConfigChange(ctx context.Context, cfg *config.Config) {
	if p == nil {
		return
	}

	p.currentOptions.Store(cfg.Options)
	if err := p.setHandlers(cfg.Options); err != nil {
		log.Error(context.TODO()).Err(err).Msg("proxy: failed to update proxy handlers from configuration settings")
	}
	if state, err := newProxyStateFromConfig(cfg); err != nil {
		log.Error(context.TODO()).Err(err).Msg("proxy: failed to update proxy state from configuration settings")
	} else {
		p.state.Store(state)
	}
}

func (p *Proxy) setHandlers(opts *config.Options) error {
	if len(opts.GetAllPolicies()) == 0 {
		log.Warn(context.TODO()).Msg("proxy: configuration has no policies")
	}
	r := httputil.NewRouter()
	r.NotFoundHandler = httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return httputil.NewError(http.StatusNotFound, fmt.Errorf("%s route unknown", r.Host))
	})
	r.SkipClean(true)
	r.StrictSlash(true)
	r.HandleFunc("/robots.txt", p.RobotsTxt).Methods(http.MethodGet)
	// dashboard handlers are registered to all routes
	r = p.registerDashboardHandlers(r)

	forwardAuthURL, err := opts.GetForwardAuthURL()
	if err != nil {
		return err
	}
	if forwardAuthURL != nil {
		// if a forward auth endpoint is set, register its handlers
		h := r.Host(forwardAuthURL.Hostname()).Subrouter()
		h.PathPrefix("/").Handler(p.registerFwdAuthHandlers())
	}

	p.currentRouter.Store(r)
	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.currentRouter.Load().(*mux.Router).ServeHTTP(w, r)
}
