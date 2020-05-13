package config

import (
	"context"
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
	for _, cert := range options.Certificates {
		if err := cm.CacheUnmanagedTLSCertificate(cert, nil); err != nil {
			return nil, fmt.Errorf("config: failed caching cert: %w", err)
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

func (mgr *autocertManager) update(options *Options) error {
	if !options.AutoCert {
		return nil
	}

	cm, err := mgr.getConfig(options)
	if err != nil {
		return err
	}

	for _, domain := range options.sourceHostnames() {
		cert, err := cm.CacheManagedCertificate(domain)
		if err != nil {
			log.Info().Str("domain", domain).Msg("obtaining certificate")
			err = cm.ObtainCert(context.Background(), domain, false)
			if err != nil {
				return fmt.Errorf("config: failed to obtain client certificate: %w", err)
			}
			cert, err = cm.CacheManagedCertificate(domain)
		}
		if err == nil && cert.NeedsRenewal(cm) {
			log.Info().Str("domain", domain).Msg("renewing certificate")
			err = cm.RenewCert(context.Background(), domain, false)
			if err != nil {
				return fmt.Errorf("config: failed to renew client certificate: %w", err)
			}
			cert, err = cm.CacheManagedCertificate(domain)
		}
		if err == nil {
			options.Certificates = append(options.Certificates, cert.Certificate)
		} else {
			log.Error().Err(err).Msg("config: failed to obtain client certificate")
		}
	}
	return nil
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
