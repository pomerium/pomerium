// Package autocert implements automatic management of TLS certificates.
package autocert

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libp2p/go-reuseport"
	"github.com/mholt/acmez/v3/acme"
	"github.com/pires/go-proxyproto"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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
	acmeTemplate certmagic.ACMEIssuer

	mu        sync.RWMutex
	config    *config.Config
	certmagic *certmagic.Config
	acmeMgr   atomic.Pointer[certmagic.ACMEIssuer]
	srv       *http.Server

	acmeTLSALPNLock     sync.Mutex
	acmeTLSALPNPort     string
	acmeTLSALPNListener net.Listener
	acmeTLSALPNConfig   *tls.Config

	*ocspCache

	config.ChangeDispatcher
}

// New creates a new autocert manager.
func New(ctx context.Context, src config.Source) (*Manager, error) {
	return newManager(ctx, src, certmagic.DefaultACME, renewalInterval)
}

func newManager(
	ctx context.Context,
	src config.Source,
	acmeTemplate certmagic.ACMEIssuer,
	checkInterval time.Duration,
) (*Manager, error) {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "autocert-manager")
	})

	ocspRespCache, err := newOCSPCache(ocspRespCacheSize)
	if err != nil {
		return nil, err
	}

	logger := getCertMagicLogger()
	acmeTemplate.Logger = logger

	mgr := &Manager{
		src:          src,
		acmeTemplate: acmeTemplate,
		ocspCache:    ocspRespCache,
	}

	// set certmagic default storage cache, otherwise cert renewal loop will be based off
	// certmagic's own default location
	certmagicStorage, err := GetCertMagicStorage(ctx, src.GetConfig().Options.AutocertOptions.Folder)
	if err != nil {
		return nil, err
	}
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(_ certmagic.Certificate) (*certmagic.Config, error) {
			return mgr.certmagic, nil
		},
		Logger: logger,
	})
	mgr.certmagic = certmagic.New(cache, certmagic.Config{
		Logger:  logger,
		Storage: certmagicStorage,
	})

	err = mgr.update(ctx, src.GetConfig())
	if err != nil {
		return nil, err
	}
	mgr.src.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		err := mgr.update(ctx, cfg)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("autocert: error updating config")
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
				cache.Stop()
				return
			case <-ticker.C:
				err := mgr.renewConfigCerts(ctx)
				if err != nil {
					log.Ctx(ctx).Error().Err(err).Msg("autocert: error updating config")
					return
				}
			}
		}
	}()
	return mgr, nil
}

func (mgr *Manager) getCertMagicConfig(ctx context.Context, cfg *config.Config) (*certmagic.Config, error) {
	mgr.certmagic.MustStaple = cfg.Options.AutocertOptions.MustStaple
	mgr.certmagic.OnDemand = nil // disable on-demand
	var err error
	mgr.certmagic.Storage, err = GetCertMagicStorage(ctx, cfg.Options.AutocertOptions.Folder)
	if err != nil {
		return nil, err
	}
	certs, err := cfg.AllCertificates()
	if err != nil {
		return nil, err
	}
	// add existing certs to the cache, and staple OCSP
	for _, cert := range certs {
		if _, err := mgr.certmagic.CacheUnmanagedTLSCertificate(ctx, cert, nil); err != nil {
			return nil, fmt.Errorf("config: failed caching cert: %w", err)
		}
	}
	acmeMgr := certmagic.NewACMEIssuer(mgr.certmagic, mgr.acmeTemplate)
	acmeMgr.DisableHTTPChallenge = !shouldEnableHTTPChallenge(cfg)
	err = configureCertificateAuthority(acmeMgr, cfg.Options.AutocertOptions)
	if err != nil {
		return nil, err
	}
	err = configureExternalAccountBinding(acmeMgr, cfg.Options.AutocertOptions)
	if err != nil {
		return nil, err
	}
	err = configureTrustedRoots(acmeMgr, cfg.Options.AutocertOptions)
	if err != nil {
		return nil, err
	}
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
	cm, err := mgr.getCertMagicConfig(ctx, cfg)
	if err != nil {
		return err
	}

	needsReload := false
	var renew, ocsp []string
	log.Ctx(ctx).Debug().Strs("domains", sourceHostnames(cfg)).Msg("checking domains")
	for _, domain := range sourceHostnames(cfg) {
		cert, err := cm.CacheManagedCertificate(ctx, domain)
		if err != nil {
			// this happens for unmanaged certificates
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
			c = c.Strs("renew-domains", renew)
		}
		if len(ocsp) > 0 {
			c = c.Strs("ocsp-refresh", ocsp)
		}
		return c
	})
	log.Ctx(ctx).Info().Msg("updating certificates")

	cfg = mgr.src.GetConfig().Clone()
	mgr.updateServer(ctx, cfg)
	mgr.updateACMETLSALPNServer(ctx, cfg)
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
	mgr.updateACMETLSALPNServer(ctx, cfg)
	return mgr.updateAutocert(ctx, cfg)
}

// obtainCert obtains a certificate for given domain, use cached manager if cert exists there.
func (mgr *Manager) obtainCert(ctx context.Context, domain string, cm *certmagic.Config) (certmagic.Certificate, error) {
	cert, err := cm.CacheManagedCertificate(ctx, domain)
	if err != nil {
		log.Ctx(ctx).Info().Str("domain", domain).Msg("obtaining certificate")
		err = cm.ObtainCertSync(ctx, domain)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("autocert failed to obtain client certificate")
			return certmagic.Certificate{}, errObtainCertFailed
		}
		metrics.RecordAutocertRenewal()
		cert, err = cm.CacheManagedCertificate(ctx, domain)
	}
	return cert, err
}

// renewCert attempts to renew given certificate.
func (mgr *Manager) renewCert(ctx context.Context, domain string, cert certmagic.Certificate, cm *certmagic.Config) (certmagic.Certificate, error) {
	expired := time.Now().After(cert.Leaf.NotAfter)
	log.Ctx(ctx).Info().Str("domain", domain).Msg("renewing certificate")
	renewCertLock.Lock()
	err := cm.RenewCertSync(ctx, domain, false)
	renewCertLock.Unlock()
	if err != nil {
		if expired {
			return certmagic.Certificate{}, errRenewCertFailed
		}
		log.Ctx(ctx).Error().Err(err).Msg("renew client certificated failed, use existing cert")
	}
	return cm.CacheManagedCertificate(ctx, domain)
}

func (mgr *Manager) updateAutocert(ctx context.Context, cfg *config.Config) error {
	if !cfg.Options.AutocertOptions.Enable {
		mgr.acmeMgr.Store(nil)
		return nil
	}

	cm, err := mgr.getCertMagicConfig(ctx, cfg)
	if err != nil {
		return err
	}

	for _, domain := range sourceHostnames(cfg) {
		cert, err := mgr.obtainCert(ctx, domain, cm)
		if err == nil && cert.NeedsRenewal(cm) {
			cert, err = mgr.renewCert(ctx, domain, cert, cm)
		}
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("autocert: failed to obtain client certificate")
			continue
		}

		log.Ctx(ctx).Info().Strs("names", cert.Names).Msg("autocert: added certificate")
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
		li, err := net.Listen("tcp", cfg.Options.HTTPRedirectAddr)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to listen on http redirect addr")
			return
		}
		defer li.Close()

		if cfg.Options.UseProxyProtocol {
			li = &proxyproto.Listener{
				Listener:          li,
				ReadHeaderTimeout: 10 * time.Second,
			}
		}

		log.Ctx(ctx).Info().Str("addr", hsrv.Addr).Msg("starting http redirect server")
		err = hsrv.Serve(li)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to run http redirect server")
		}
	}()
	mgr.srv = hsrv
}

func (mgr *Manager) updateACMETLSALPNServer(ctx context.Context, cfg *config.Config) {
	mgr.acmeTLSALPNLock.Lock()
	defer mgr.acmeTLSALPNLock.Unlock()

	// store the updated TLS config
	mgr.acmeTLSALPNConfig = mgr.certmagic.TLSConfig().Clone()
	// if the port hasn't changed, we're done
	if mgr.acmeTLSALPNPort == cfg.ACMETLSALPNPort {
		return
	}

	// store the updated port
	mgr.acmeTLSALPNPort = cfg.ACMETLSALPNPort

	if mgr.acmeTLSALPNListener != nil {
		_ = mgr.acmeTLSALPNListener.Close()
		mgr.acmeTLSALPNListener = nil
	}

	// start the listener
	addr := net.JoinHostPort("127.0.0.1", cfg.ACMETLSALPNPort)
	ln, err := reuseport.Listen("tcp", addr)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to run acme tls alpn server")
		return
	}
	mgr.acmeTLSALPNListener = ln

	// accept connections
	go func() {
		for {
			conn, err := ln.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				continue
			}

			// initiate the TLS handshake
			mgr.acmeTLSALPNLock.Lock()
			tlsConfig := mgr.acmeTLSALPNConfig.Clone()
			mgr.acmeTLSALPNLock.Unlock()

			orig := tlsConfig.GetCertificate
			tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				log.Ctx(ctx).Info().Str("server-name", chi.ServerName).
					Msg("received request for ACME TLS ALPN certificate")
				return orig(chi)
			}

			_ = tls.Server(conn, tlsConfig).HandshakeContext(ctx)
			_ = conn.Close()
		}
	}()
}

func (mgr *Manager) handleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	return mgr.acmeMgr.Load().HandleHTTPChallenge(w, r)
}

// GetConfig gets the config.
func (mgr *Manager) GetConfig() *config.Config {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	return mgr.config
}

// configureCertificateAuthority configures the acmeMgr ACME Certificate Authority settings.
func configureCertificateAuthority(acmeMgr *certmagic.ACMEIssuer, opts config.AutocertOptions) error {
	acmeMgr.Agreed = true
	if opts.UseStaging {
		acmeMgr.CA = acmeMgr.TestCA
	}
	if opts.CA != "" {
		acmeMgr.CA = opts.CA // when a CA is specified, it overrides the staging setting
	}
	if opts.Email != "" {
		acmeMgr.Email = opts.Email
	} else {
		acmeMgr.Email = " " // intentionally set to a space so that certmagic doesn't prompt for an email address
	}
	return nil
}

// configureExternalAccountBinding configures the acmeMgr ACME External Account Binding settings.
func configureExternalAccountBinding(acmeMgr *certmagic.ACMEIssuer, opts config.AutocertOptions) error {
	if opts.EABKeyID != "" || opts.EABMACKey != "" {
		acmeMgr.ExternalAccount = &acme.EAB{}
	}
	if opts.EABKeyID != "" {
		acmeMgr.ExternalAccount.KeyID = opts.EABKeyID
	}
	if opts.EABMACKey != "" {
		_, err := base64.RawURLEncoding.DecodeString(opts.EABMACKey)
		if err != nil {
			return fmt.Errorf("config: decoding base64-urlencoded MAC Key: %w", err)
		}
		acmeMgr.ExternalAccount.MACKey = opts.EABMACKey
	}
	return nil
}

// configureTrustedRoots configures the acmeMgr x509 roots to trust when communicating with an ACME CA.
func configureTrustedRoots(acmeMgr *certmagic.ACMEIssuer, opts config.AutocertOptions) error {
	if opts.TrustedCA != "" {
		// pool effectively contains the certificate(s) in the TrustedCA base64 PEM appended to the system roots
		pool, err := cryptutil.GetCertPool(opts.TrustedCA, "")
		if err != nil {
			return fmt.Errorf("config: creating trusted certificate pool: %w", err)
		}
		acmeMgr.TrustedRoots = pool
	}
	if opts.TrustedCAFile != "" {
		// pool effectively contains the certificate(s) in TrustedCAFile appended to the system roots
		pool, err := cryptutil.GetCertPool("", opts.TrustedCAFile)
		if err != nil {
			return fmt.Errorf("config: creating trusted certificate pool: %w", err)
		}
		acmeMgr.TrustedRoots = pool
	}
	return nil
}

func sourceHostnames(cfg *config.Config) []string {
	if cfg.Options.NumPolicies() == 0 {
		return nil
	}

	dedupe := map[string]struct{}{}
	for p := range cfg.Options.GetAllPolicies() {
		if h := eligibleHostname(p); h != "" {
			dedupe[h] = struct{}{}
		}
	}
	if cfg.Options.AuthenticateURLString != "" {
		if u, _ := cfg.Options.GetAuthenticateURL(); u != nil {
			dedupe[u.Hostname()] = struct{}{}
		}
	}

	// remove any hosted authenticate URLs
	for _, domain := range urlutil.HostedAuthenticateDomains {
		delete(dedupe, domain)
	}

	var h []string
	for k := range dedupe {
		h = append(h, k)
	}
	sort.Strings(h)

	return h
}

var eligibleSchemes = map[string]struct{}{
	"https":     {},
	"tcp+https": {},
	"udp+https": {},
}

// eligibleHostname accepts a route and returns the hostname, if eligible for use
// with autocert, or the empty string if not.
func eligibleHostname(p *config.Policy) string {
	u, _ := urlutil.ParseAndValidateURL(p.From)
	if u == nil || strings.Contains(u.Host, "*") {
		return ""
	} else if _, ok := eligibleSchemes[u.Scheme]; !ok {
		return ""
	}
	return u.Hostname()
}

func shouldEnableHTTPChallenge(cfg *config.Config) bool {
	if cfg == nil || cfg.Options == nil {
		return false
	}

	_, p, err := net.SplitHostPort(cfg.Options.HTTPRedirectAddr)
	if err != nil {
		return false
	}

	return p == "80"
}
