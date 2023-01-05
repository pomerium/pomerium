// Package config implements derived certs in the Pomerium Configuration
package config

import (
	"bytes"
	"crypto/tls"
	"fmt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/derivecert"
)

type builder struct {
	psk       []byte
	ca        *derivecert.CA
	caCertPEM []byte

	domain string
	certs  []tls.Certificate
}

// NewBuilder returns a new derived certs config builder with caching
func NewBuilder() func(*config.Config) error {
	return new(builder).Build
}

func (x *builder) Build(cfg *config.Config) error {
	if cfg.Options.DeriveInternalDomainCert == nil {
		return nil
	}

	psk, err := cfg.Options.GetSharedKey()
	if err != nil {
		return fmt.Errorf("shared key: %w", err)
	}

	if err = x.buildCA(psk); err != nil {
		return err
	}

	if err = x.buildCert(*cfg.Options.DeriveInternalDomainCert); err != nil {
		return err
	}

	cfg.DerivedCAPEM = x.caCertPEM
	cfg.DerivedCertificates = x.certs
	return nil
}

func (x *builder) buildCA(psk []byte) error {
	if bytes.Equal(x.psk, psk) {
		return nil
	}

	ca, err := derivecert.NewCA(psk)
	if err != nil {
		return fmt.Errorf("building certificate authority from shared key: %w", err)
	}

	pem, err := ca.PEM()
	if err != nil {
		return fmt.Errorf("encode derived CA to PEM: %w", err)
	}

	x.psk = psk
	x.ca = ca
	x.caCertPEM = pem.Cert

	return nil
}

func (x *builder) buildCert(domain string) error {
	if x.domain == domain {
		return nil
	}

	certPEM, err := x.ca.NewServerCert([]string{domain})
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}

	cert, err := certPEM.TLS()
	if err != nil {
		return fmt.Errorf("parse TLS cert: %w", err)
	}

	x.domain = domain
	x.certs = []tls.Certificate{cert}

	return nil
}
