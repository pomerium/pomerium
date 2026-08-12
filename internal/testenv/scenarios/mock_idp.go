package scenarios

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

type IDP struct {
	IDPOptions
	id      values.Value[string]
	url     values.Value[string]
	mockIDP *mockidp.IDP
}

type IDPOptions struct {
	enableTLS        bool
	enableDeviceAuth bool
	enablePKCE       bool
	rotationMode     mockidp.RotationMode
	accessTokenTTL   time.Duration
}

type IDPOption func(*IDPOptions)

func (o *IDPOptions) apply(opts ...IDPOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithEnableTLS(enableTLS bool) IDPOption {
	return func(o *IDPOptions) {
		o.enableTLS = enableTLS
	}
}

func WithEnableDeviceAuth(enableDeviceAuth bool) IDPOption {
	return func(o *IDPOptions) {
		o.enableDeviceAuth = enableDeviceAuth
	}
}

func WithEnablePKCE(enablePKCE bool) IDPOption {
	return func(o *IDPOptions) {
		o.enablePKCE = enablePKCE
	}
}

// WithRotationMode selects how the IdP treats a presented refresh token. The
// zero value keeps the historical behavior, where a presented token stays valid
// forever.
func WithRotationMode(mode RotationMode) IDPOption {
	return func(o *IDPOptions) {
		o.rotationMode = mode
	}
}

// WithAccessTokenTTL sets the access token lifetime the provider reports. A
// short one lets a test reach the state where a stored token is due for refresh
// without waiting out a real provider's hour.
func WithAccessTokenTTL(d time.Duration) IDPOption {
	return func(o *IDPOptions) {
		o.accessTokenTTL = d
	}
}

// Attach implements testenv.Modifier.
func (idp *IDP) Attach(ctx context.Context) {
	env := testenv.EnvFromContext(ctx)

	idpURL := env.SubdomainURL("mock-idp")

	var tlsConfig values.Value[*tls.Config]
	if idp.enableTLS {
		tlsConfig = values.Bind(idpURL, func(urlStr string) *tls.Config {
			u, _ := url.Parse(urlStr)
			cert := env.NewServerCert(&x509.Certificate{
				DNSNames: []string{u.Hostname()},
			})
			return &tls.Config{
				RootCAs:      env.ServerCAs(),
				Certificates: []tls.Certificate{tls.Certificate(*cert)},
				NextProtos:   []string{"http/1.1", "h2"},
			}
		})
	}

	up := upstreams.HTTP(tlsConfig, upstreams.WithDisplayName("IDP"))

	idp.url = values.Bind2(idpURL, up.Addr(), func(urlStr string, addr string) string {
		u, _ := url.Parse(urlStr)
		host, _, _ := net.SplitHostPort(u.Host)
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			panic("bug: " + err.Error())
		}
		return u.ResolveReference(&url.URL{
			Host: fmt.Sprintf("%s:%s", host, port),
		}).String()
	})

	idp.id = values.Bind2(idp.url, env.AuthenticateURL(), func(idpUrl, authUrl string) string {
		provider := identity.Provider{
			AuthenticateServiceUrl: authUrl,
			ClientId:               "CLIENT_ID",
			ClientSecret:           "CLIENT_SECRET",
			Type:                   "oidc",
			Scopes:                 []string{"openid", "email", "profile"},
			Url:                    idpUrl,
		}
		return provider.Hash()
	})

	idp.mockIDP.Register(up.Router())

	env.AddUpstream(up)
}

// Modify implements testenv.Modifier.
func (idp *IDP) Modify(cfg *config.Config) {
	cfg.Options.Provider = "oidc"
	cfg.Options.ProviderURL = idp.url.Value()
	cfg.Options.ClientID = "CLIENT_ID"
	cfg.Options.ClientSecret = "CLIENT_SECRET"
	cfg.Options.Scopes = []string{"openid", "email", "profile"}
}

var _ testenv.Modifier = (*IDP)(nil)

func NewIDP(users []*mockidp.User, opts ...IDPOption) *IDP {
	options := IDPOptions{
		enableTLS: true,
	}
	options.apply(opts...)

	return &IDP{
		IDPOptions: options,
		mockIDP: mockidp.New(mockidp.Config{
			Users:            users,
			EnableDeviceAuth: options.enableDeviceAuth,
			EnablePKCE:       options.enablePKCE,
			RotationMode:     options.rotationMode,
			AccessTokenTTL:   options.accessTokenTTL,
		}),
	}
}

// ValidRefreshTokenCount reports how many refresh tokens the provider would
// still accept, so a scenario can assert what a rotation chain left behind.
func (idp *IDP) ValidRefreshTokenCount() int { return idp.mockIDP.ValidRefreshTokenCount() }

// RefreshCount reports how many refresh_token grants the provider has served,
// which is what a test asserting "one presentation" has to measure.
func (idp *IDP) RefreshCount() int64 { return idp.mockIDP.RefreshCount() }

type User = mockidp.User

// RotationMode selects the provider's refresh-token rotation semantics, so
// callers configuring a scenario need not import the mock directly.
type RotationMode = mockidp.RotationMode

// RotateReuseDetect is the mode a scenario needs to make a replay visible: the
// provider revokes the whole grant family when a consumed token is presented
// again. Other modes are available through mockidp directly.
const RotateReuseDetect = mockidp.RotateReuseDetect
