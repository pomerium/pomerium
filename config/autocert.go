package config

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/caddyserver/certmagic"

	"github.com/pomerium/pomerium/internal/log"
)

// AutocertOptions contains the options to control the behavior of autocert.
type AutocertOptions struct {
	// Enable enables fully automated certificate management including issuance
	// and renewal from LetsEncrypt. Must be used in conjunction with Folder.
	Enable bool `mapstructure:"autocert" yaml:"autocert,omitempty"`

	// UseStaging tells autocert to use Let's Encrypt's staging CA which
	// has less strict usage limits then the (default) production CA.
	//
	// https://letsencrypt.org/docs/staging-environment/
	UseStaging bool `mapstructure:"autocert_use_staging" yaml:"autocert_use_staging,omitempty"`

	// MustStaple will cause autocert to request a certificate with
	// status_request extension. This will allow the TLS client (the browser)
	// to fail immediately if Pomerium failed to get an OCSP staple.
	// See also https://tools.ietf.org/html/rfc7633
	// Only used when Enable is true.
	MustStaple bool `mapstructure:"autocert_must_staple" yaml:"autocert_must_staple,omitempty"`

	// Folder specifies the location to store, and load autocert managed
	// TLS certificates.
	// defaults to $XDG_DATA_HOME/pomerium
	Folder string `mapstructure:"autocert_dir" yaml:"autocert_dir,omitempty"`
}

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
		cm.MustStaple = options.AutocertOptions.MustStaple
	}

	cm.OnDemand = nil // disable on-demand
	cm.Storage = &certmagic.FileStorage{Path: options.AutocertOptions.Folder}
	// add existing certs to the cache, and staple OCSP
	for _, cert := range options.Certificates {
		if err := cm.CacheUnmanagedTLSCertificate(cert, nil); err != nil {
			return nil, fmt.Errorf("config: failed caching cert: %w", err)
		}
	}
	acmeMgr := certmagic.NewACMEManager(cm, certmagic.DefaultACME)
	acmeMgr.Agreed = true
	if options.AutocertOptions.UseStaging {
		acmeMgr.CA = certmagic.LetsEncryptStagingCA
	}
	acmeMgr.DisableTLSALPNChallenge = true
	cm.Issuer = acmeMgr
	mgr.acmeMgr = acmeMgr

	return cm, nil
}

func (mgr *autocertManager) update(options *Options) error {
	if !options.AutocertOptions.Enable {
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
