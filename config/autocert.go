package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/caddyserver/certmagic"

	"github.com/pomerium/pomerium/internal/log"
)

// AutocertManager manages Let's Encrypt certificates based on configuration options.
var AutocertManager = newAutocertManager()

type autocertManager struct {
	mu        sync.RWMutex
	certmagic *certmagic.Config
	acmeMgr   *certmagic.ACMEManager
}

func newAutocertManager() *autocertManager {
	mgr := &autocertManager{}
	return mgr
}

func (mgr *autocertManager) getConfig(options *Options) (*certmagic.Config, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	cm := mgr.certmagic
	if cm == nil {
		cm = certmagic.NewDefault()
	}

	cm.OnDemand = nil // disable on-demand
	cm.Storage = &certmagic.FileStorage{Path: options.AutoCertFolder}
	// add existing certs to the cache, and staple OCSP
	if options.TLSConfig != nil {
		for _, cert := range options.TLSConfig.Certificates {
			if err := cm.CacheUnmanagedTLSCertificate(cert, nil); err != nil {
				return nil, fmt.Errorf("config: failed caching cert: %w", err)
			}
		}
	}
	acmeMgr := certmagic.NewACMEManager(cm, certmagic.DefaultACME)
	acmeMgr.Agreed = true
	if options.AutoCertUseStaging {
		acmeMgr.CA = certmagic.LetsEncryptStagingCA
	}
	acmeMgr.DisableTLSALPNChallenge = true
	cm.Issuer = acmeMgr
	mgr.acmeMgr = acmeMgr

	return cm, nil
}

func (mgr *autocertManager) update(options *Options) (*tls.Config, error) {
	if !options.AutoCert {
		return options.TLSConfig, nil
	}

	cm, err := mgr.getConfig(options)
	if err != nil {
		return nil, err
	}

	tlsConfig := newTLSConfigIfEmpty(options.TLSConfig).Clone()
	for _, domain := range options.sourceHostnames() {
		cert, err := cm.CacheManagedCertificate(domain)
		if err != nil {
			log.Info().Str("domain", domain).Msg("obtaining certificate")
			err = cm.ObtainCert(context.Background(), domain, false)
			if err != nil {
				return nil, fmt.Errorf("config: failed to obtain client certificate: %w", err)
			}
			cert, err = cm.CacheManagedCertificate(domain)
		}
		if err == nil {
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert.Certificate)
		}
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

func (mgr *autocertManager) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	mgr.mu.RLock()
	acmeMgr := mgr.acmeMgr
	mgr.mu.RUnlock()
	if acmeMgr == nil {
		return false
	}
	return acmeMgr.HandleHTTPChallenge(w, r)
}

// newTLSConfigIfEmpty returns an opinionated TLS configuration if config is nil.
// See :
// https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
// https://blog.cloudflare.com/exposing-go-on-the-internet/
// https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
// https://github.com/golang/go/blob/df91b8044dbe790c69c16058330f545be069cc1f/src/crypto/tls/common.go#L919
func newTLSConfigIfEmpty(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig != nil {
		return tlsConfig
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Prioritize cipher suites sped up by AES-NI (AES-GCM)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		// Use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		// HTTP/2 must be enabled manually when using http.Serve
		NextProtos: []string{"h2", "http/1.1"},
	}
}
