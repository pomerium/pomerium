package scenarios

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"net/url"

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

// Attach implements testenv.Modifier.
func (idp *IDP) Attach(ctx context.Context) {
	env := testenv.EnvFromContext(ctx)

	idpURL := env.SubdomainURL("mock-idp")

	var tlsConfig values.Value[*tls.Config]
	if idp.enableTLS {
		tlsConfig = values.Bind(idpURL, func(_ string) *tls.Config {
			cert := env.NewServerCert(&x509.Certificate{
				DNSNames: []string{"*.sslip.io"},
			})
			return &tls.Config{
				RootCAs:      env.ServerCAs(),
				Certificates: []tls.Certificate{tls.Certificate(*cert)},
				NextProtos:   []string{"http/1.1", "h2"},
			}
		})
	}

	up := upstreams.HTTP(tlsConfig, upstreams.WithDisplayName("IDP"))

	idp.url = values.Bind2(idpURL, up.Addr(), func(urlStr string, addrStr string) string {
		u, _ := url.Parse(urlStr)
		addr := netip.MustParseAddrPort(addrStr)
		host := testenv.GetSubDomainForAddress("mock-idp", addr.Addr())
		return u.ResolveReference(&url.URL{
			Host: fmt.Sprintf("%s:%d", host, addr.Port()),
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
		}),
	}
}

type User = mockidp.User
