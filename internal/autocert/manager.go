// Package autocert implements automatic management of TLS certificates.
package autocert

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/certmagic"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
)

// Manager manages TLS certificates.
type Manager struct {
	src config.Source

	mu        sync.RWMutex
	config    *config.Config
	certmagic *certmagic.Config
	acmeMgr   atomic.Value
	srv       *http.Server

	config.ChangeDispatcher
}

// New creates a new autocert manager.
func New(src config.Source) (*Manager, error) {
	// set certmagic default storage cache, otherwise cert renewal loop will be based off
	// certmagic's own default location
	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: src.GetConfig().Options.AutocertOptions.Folder,
	}

	mgr := &Manager{
		src:       src,
		certmagic: certmagic.NewDefault(),
	}
	err := mgr.update(src.GetConfig())
	if err != nil {
		return nil, err
	}
	mgr.src.OnConfigChange(func(cfg *config.Config) {
		err := mgr.update(cfg)
		if err != nil {
			log.Error().Err(err).Msg("autocert: error updating config")
			return
		}

		cfg = mgr.GetConfig()
		mgr.Trigger(cfg)
	})
	return mgr, nil
}

func (mgr *Manager) getCertMagicConfig(options *config.Options) (*certmagic.Config, error) {
	mgr.certmagic.MustStaple = options.AutocertOptions.MustStaple
	mgr.certmagic.OnDemand = nil // disable on-demand
	mgr.certmagic.Storage = &certmagic.FileStorage{Path: options.AutocertOptions.Folder}
	// add existing certs to the cache, and staple OCSP
	for _, cert := range options.Certificates {
		if err := mgr.certmagic.CacheUnmanagedTLSCertificate(cert, nil); err != nil {
			return nil, fmt.Errorf("config: failed caching cert: %w", err)
		}
	}
	acmeMgr := certmagic.NewACMEManager(mgr.certmagic, certmagic.DefaultACME)
	acmeMgr.Agreed = true
	if options.AutocertOptions.UseStaging {
		acmeMgr.CA = certmagic.LetsEncryptStagingCA
	}
	acmeMgr.DisableTLSALPNChallenge = true
	mgr.certmagic.Issuer = acmeMgr
	mgr.acmeMgr.Store(acmeMgr)

	return mgr.certmagic, nil
}

func (mgr *Manager) update(cfg *config.Config) error {
	cfg = cfg.Clone()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	defer func() { mgr.config = cfg }()

	mgr.updateServer(cfg)
	return mgr.updateAutocert(cfg)
}

func (mgr *Manager) updateAutocert(cfg *config.Config) error {
	if !cfg.Options.AutocertOptions.Enable {
		return nil
	}

	cm, err := mgr.getCertMagicConfig(cfg.Options)
	if err != nil {
		return err
	}

	for _, domain := range sourceHostnames(cfg) {
		cert, err := cm.CacheManagedCertificate(domain)
		if err != nil {
			log.Info().Str("domain", domain).Msg("obtaining certificate")
			err = cm.ObtainCert(context.Background(), domain, false)
			if err != nil {
				return fmt.Errorf("autocert: failed to obtain client certificate: %w", err)
			}
			cert, err = cm.CacheManagedCertificate(domain)
		}
		if err == nil && cert.NeedsRenewal(cm) {
			log.Info().Str("domain", domain).Msg("renewing certificate")
			err = cm.RenewCert(context.Background(), domain, false)
			if err != nil {
				return fmt.Errorf("autocert: failed to renew client certificate: %w", err)
			}
			cert, err = cm.CacheManagedCertificate(domain)
		}
		if err == nil {
			log.Info().Strs("names", cert.Names).Msg("autocert: added certificate")
			cfg.Options.Certificates = append(cfg.Options.Certificates, cert.Certificate)
		} else {
			log.Error().Err(err).Msg("autocert: failed to obtain client certificate")
		}
	}

	return nil
}

func (mgr *Manager) updateServer(cfg *config.Config) {
	if mgr.srv != nil {
		// nothing to do if the address hasn't changed
		if mgr.srv.Addr == cfg.Options.HTTPRedirectAddr {
			return
		}
		// close immediately, don't care about the error
		_ = mgr.srv.Close()
		mgr.srv = nil
	}

	if cfg.Options.HTTPRedirectAddr == "" {
		return
	}

	redirect := httputil.RedirectHandler()

	hsrv := &http.Server{
		Addr: cfg.Options.HTTPRedirectAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mgr.handleHTTPChallenge(w, r) {
				return
			}
			redirect.ServeHTTP(w, r)
		}),
	}
	go func() {
		log.Info().Str("addr", hsrv.Addr).Msg("starting http redirect server")
		err := hsrv.ListenAndServe()
		if err != nil {
			log.Error().Err(err).Msg("failed to run http redirect server")
		}
	}()
	mgr.srv = hsrv
}

func (mgr *Manager) handleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	acmeMgr := mgr.acmeMgr.Load().(*certmagic.ACMEManager)
	if acmeMgr == nil {
		return false
	}
	return acmeMgr.HandleHTTPChallenge(w, r)
}

// GetConfig gets the config.
func (mgr *Manager) GetConfig() *config.Config {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.config
}

func sourceHostnames(cfg *config.Config) []string {
	if len(cfg.Options.Policies) == 0 {
		return nil
	}

	dedupe := map[string]struct{}{}
	for _, p := range cfg.Options.Policies {
		dedupe[p.Source.Hostname()] = struct{}{}
	}
	if cfg.Options.AuthenticateURL != nil {
		dedupe[cfg.Options.AuthenticateURL.Hostname()] = struct{}{}
	}

	var h []string
	for k := range dedupe {
		h = append(h, k)
	}
	sort.Strings(h)

	return h
}
