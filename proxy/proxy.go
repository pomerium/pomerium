// Package proxy is a pomerium service that provides reverse proxying of
// internal routes. The proxy packages interoperates with other pomerium
// services over RPC in order to make access control decisions about a
// given incoming request.
package proxy

import (
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
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	// authenticate urls
	dashboardPath = "/.pomerium"
	signinURL     = "/.pomerium/sign_in"
	signoutURL    = "/.pomerium/sign_out"
	refreshURL    = "/.pomerium/refresh"
)

// ValidateOptions checks that proper configuration settings are set to create
// a proper Proxy instance
func ValidateOptions(o *config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("proxy: invalid 'SHARED_SECRET': %w", err)
	}

	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("proxy: invalid 'COOKIE_SECRET': %w", err)
	}

	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}

	if err := urlutil.ValidateURL(o.AuthorizeURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHORIZE_SERVICE_URL': %w", err)
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
		return int64(len(p.currentOptions.Load().Policies))
	})

	return p, nil
}

// OnConfigChange updates internal structures based on config.Options
func (p *Proxy) OnConfigChange(cfg *config.Config) {
	if p == nil {
		return
	}

	log.Info().Str("checksum", fmt.Sprintf("%x", cfg.Options.Checksum())).Msg("proxy: updating options")
	p.currentOptions.Store(cfg.Options)
	p.setHandlers(cfg.Options)
	if state, err := newProxyStateFromConfig(cfg); err != nil {
		log.Error().Err(err).Msg("proxy: failed to update proxy state from configuration settings")
	} else {
		p.state.Store(state)
	}
}

func (p *Proxy) setHandlers(opts *config.Options) {
	if len(opts.Policies) == 0 {
		log.Warn().Msg("proxy: configuration has no policies")
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

	if opts.ForwardAuthURL != nil {
		// if a forward auth endpoint is set, register its handlers
		h := r.Host(opts.ForwardAuthURL.Hostname()).Subrouter()
		h.PathPrefix("/").Handler(p.registerFwdAuthHandlers())
	}

	p.currentRouter.Store(r)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.currentRouter.Load().(*mux.Router).ServeHTTP(w, r)
}
