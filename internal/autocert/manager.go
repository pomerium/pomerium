// Package autocert implements automatic management of TLS certificates.
package autocert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/rs/zerolog"
	"go.uber.org/zap"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

var (
	errObtainCertFailed = errors.New("obtain cert failed")
	errRenewCertFailed  = errors.New("renew cert failed")

	// RenewCert is not thread-safe
	renewCertLock sync.Mutex
)

const (
	ocspRespCacheSize = 50000
	renewalInterval   = time.Minute * 10
	renewalTimeout    = time.Hour
)

// Manager manages TLS certificates.
type Manager struct {
	src          config.Source
	acmeTemplate certmagic.ACMEManager

	mu        sync.RWMutex
	config    *config.Config
	certmagic *certmagic.Config
	acmeMgr   atomic.Value
	srv       *http.Server

	*ocspCache

	config.ChangeDispatcher
}

// New creates a new autocert manager.
func New(src config.Source) (*Manager, error) {
	return newManager(context.Background(), src, certmagic.DefaultACME, renewalInterval)
}

func newManager(ctx context.Context,
	src config.Source,
	acmeTemplate certmagic.ACMEManager,
	checkInterval time.Duration,
) (*Manager, error) {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "autocert-manager")
	})

	ocspRespCache, err := newOCSPCache(ocspRespCacheSize)
	if err != nil {
		return nil, err
	}

	certmagicConfig := certmagic.NewDefault()
	// set certmagic default storage cache, otherwise cert renewal loop will be based off
	// certmagic's own default location
	certmagicConfig.Storage = &certmagic.FileStorage{
		Path: src.GetConfig().Options.AutocertOptions.Folder,
	}

	logger := log.ZapLogger().With(zap.String("service", "autocert"))
	certmagicConfig.Logger = logger
	acmeTemplate.Logger = logger

	mgr := &Manager{
		src:          src,
		acmeTemplate: acmeTemplate,
		certmagic:    certmagicConfig,
		ocspCache:    ocspRespCache,
	}
	err = mgr.update(ctx, src.GetConfig())
	if err != nil {
		return nil, err
	}
	mgr.src.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		err := mgr.update(ctx, cfg)
		if err != nil {
			log.Error(ctx).Err(err).Msg("autocert: error updating config")
			return
		}

		cfg = mgr.GetConfig()
		mgr.Trigger(ctx, cfg)
	})
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := mgr.renewConfigCerts(ctx)
				if err != nil {
					log.Error(ctx).Err(err).Msg("autocert: error updating config")
					return
				}
			}
		}
	}()
	return mgr, nil
}

func (mgr *Manager) getCertMagicConfig(cfg *config.Config) (*certmagic.Config, error) {
	mgr.certmagic.MustStaple = cfg.Options.AutocertOptions.MustStaple
	mgr.certmagic.OnDemand = nil // disable on-demand
	mgr.certmagic.Storage = &certmagic.FileStorage{Path: cfg.Options.AutocertOptions.Folder}
	certs, err := cfg.AllCertificates()
	if err != nil {
		return nil, err
	}
	// add existing certs to the cache, and staple OCSP
	for _, cert := range certs {
		if err := mgr.certmagic.CacheUnmanagedTLSCertificate(cert, nil); err != nil {
			return nil, fmt.Errorf("config: failed caching cert: %w", err)
		}
	}
	acmeMgr := certmagic.NewACMEManager(mgr.certmagic, mgr.acmeTemplate)
	acmeMgr.Agreed = true
	if cfg.Options.AutocertOptions.UseStaging {
		acmeMgr.CA = acmeMgr.TestCA
	}
	acmeMgr.DisableTLSALPNChallenge = true
	mgr.certmagic.Issuers = []certmagic.Issuer{acmeMgr}
	mgr.acmeMgr.Store(acmeMgr)

	return mgr.certmagic, nil
}

func (mgr *Manager) renewConfigCerts(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, renewalTimeout)
	defer cancel()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	cfg := mgr.config
	cm, err := mgr.getCertMagicConfig(cfg)
	if err != nil {
		return err
	}

	needsReload := false
	var renew, ocsp []string
	log.Debug(ctx).Strs("domains", sourceHostnames(cfg)).Msg("checking domains")
	for _, domain := range sourceHostnames(cfg) {
		cert, err := cm.CacheManagedCertificate(domain)
		if err != nil {
			log.Error(ctx).Err(err).Str("domain", domain).Msg("get cert")
			continue
		}
		if cert.NeedsRenewal(cm) {
			renew = append(renew, domain)
			needsReload = true
		}
		if mgr.ocspCache.updated(domain, cert.OCSPStaple) {
			ocsp = append(ocsp, domain)
			needsReload = true
		}
	}
	if !needsReload {
		return nil
	}

	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		if len(renew) > 0 {
			c = c.Strs("renew_domains", renew)
		}
		if len(ocsp) > 0 {
			c = c.Strs("ocsp_refresh", ocsp)
		}
		return c
	})
	log.Info(ctx).Msg("updating certificates")

	cfg = mgr.src.GetConfig().Clone()
	mgr.updateServer(ctx, cfg)
	if err := mgr.updateAutocert(ctx, cfg); err != nil {
		return err
	}

	mgr.config = cfg
	mgr.Trigger(ctx, cfg)
	return nil
}

func (mgr *Manager) update(ctx context.Context, cfg *config.Config) error {
	cfg = cfg.Clone()

	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	defer func() { mgr.config = cfg }()

	mgr.updateServer(ctx, cfg)
	return mgr.updateAutocert(ctx, cfg)
}

// obtainCert obtains a certificate for given domain, use cached manager if cert exists there.
func (mgr *Manager) obtainCert(ctx context.Context, domain string, cm *certmagic.Config) (certmagic.Certificate, error) {
	cert, err := cm.CacheManagedCertificate(domain)
	if err != nil {
		log.Info(ctx).Str("domain", domain).Msg("obtaining certificate")
		err = cm.ObtainCert(ctx, domain, false)
		if err != nil {
			log.Error(ctx).Err(err).Msg("autocert failed to obtain client certificate")
			return certmagic.Certificate{}, errObtainCertFailed
		}
		metrics.RecordAutocertRenewal()
		cert, err = cm.CacheManagedCertificate(domain)
	}
	return cert, err
}

// renewCert attempts to renew given certificate.
func (mgr *Manager) renewCert(ctx context.Context, domain string, cert certmagic.Certificate, cm *certmagic.Config) (certmagic.Certificate, error) {
	expired := time.Now().After(cert.Leaf.NotAfter)
	log.Info(ctx).Str("domain", domain).Msg("renewing certificate")
	renewCertLock.Lock()
	err := cm.RenewCert(ctx, domain, false)
	renewCertLock.Unlock()
	if err != nil {
		if expired {
			return certmagic.Certificate{}, errRenewCertFailed
		}
		log.Warn(ctx).Err(err).Msg("renew client certificated failed, use existing cert")
	}
	return cm.CacheManagedCertificate(domain)
}

func (mgr *Manager) updateAutocert(ctx context.Context, cfg *config.Config) error {
	if !cfg.Options.AutocertOptions.Enable {
		return nil
	}

	cm, err := mgr.getCertMagicConfig(cfg)
	if err != nil {
		return err
	}

	for _, domain := range sourceHostnames(cfg) {
		cert, err := mgr.obtainCert(ctx, domain, cm)
		if err != nil && errors.Is(err, errObtainCertFailed) {
			return fmt.Errorf("autocert: failed to obtain client certificate: %w", err)
		}
		if err == nil && cert.NeedsRenewal(cm) {
			cert, err = mgr.renewCert(ctx, domain, cert, cm)
		}
		if err != nil && errors.Is(err, errRenewCertFailed) {
			return fmt.Errorf("autocert: failed to renew client certificate: %w", err)
		}
		if err != nil {
			log.Error(ctx).Err(err).Msg("autocert: failed to obtain client certificate")
			continue
		}

		log.Info(ctx).Strs("names", cert.Names).Msg("autocert: added certificate")
		cfg.AutoCertificates = append(cfg.AutoCertificates, cert.Certificate)
	}

	metrics.RecordAutocertCertificates(cfg.AutoCertificates)

	return nil
}

func (mgr *Manager) updateServer(ctx context.Context, cfg *config.Config) {
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
		log.Info(ctx).Str("addr", hsrv.Addr).Msg("starting http redirect server")
		err := hsrv.ListenAndServe()
		if err != nil {
			log.Error(ctx).Err(err).Msg("failed to run http redirect server")
		}
	}()
	mgr.srv = hsrv
}

func (mgr *Manager) handleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	obj := mgr.acmeMgr.Load()
	if obj == nil {
		return false
	}
	acmeMgr := obj.(*certmagic.ACMEManager)
	return acmeMgr.HandleHTTPChallenge(w, r)
}

// GetConfig gets the config.
func (mgr *Manager) GetConfig() *config.Config {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.config
}

func sourceHostnames(cfg *config.Config) []string {
	policies := cfg.Options.GetAllPolicies()

	if len(policies) == 0 {
		return nil
	}

	dedupe := map[string]struct{}{}
	for _, p := range policies {
		dedupe[p.Source.Hostname()] = struct{}{}
	}
	if cfg.Options.AuthenticateURLString != "" {
		u, _ := cfg.Options.GetAuthenticateURL()
		if u != nil {
			dedupe[u.Hostname()] = struct{}{}
		}
	}

	var h []string
	for k := range dedupe {
		h = append(h, k)
	}
	sort.Strings(h)

	return h
}
