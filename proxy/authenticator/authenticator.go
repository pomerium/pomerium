package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// Authenticator provides the authenticate service interface
type Authenticator interface {
	// Redeem takes a code and returns a validated session or an error
	Redeem(string) (*RedeemResponse, error)
	// Refresh attempts to refresh a valid session with a refresh token. Returns a new access token
	// and expiration, or an error.
	Refresh(string) (string, time.Time, error)
	// Validate evaluates a given oidc id_token for validity. Returns validity and any error.
	Validate(string) (bool, error)
	// Close closes the authenticator connection if any.
	Close() error
}

// New returns a new identity provider based given its name.
// Returns an error if selected provided not found or if the identity provider is not known.
func New(uri *url.URL, internalURL, OverideCertificateName, key string) (p Authenticator, err error) {
	// if no port given, assume https/443
	port := uri.Port()
	if port == "" {
		port = "443"
	}
	authEndpoint := fmt.Sprintf("%s:%s", uri.Host, port)

	cp, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if internalURL != "" {
		authEndpoint = internalURL
	}

	log.Info().Str("authEndpoint", authEndpoint).Msgf("proxy.New: grpc authenticate connection")
	cert := credentials.NewTLS(&tls.Config{RootCAs: cp})
	if OverideCertificateName != "" {
		err = cert.OverrideServerName(OverideCertificateName)
		if err != nil {
			return nil, err
		}
	}
	grpcAuth := middleware.NewSharedSecretCred(key)
	conn, err := grpc.Dial(
		authEndpoint,
		grpc.WithTransportCredentials(cert),
		grpc.WithPerRPCCredentials(grpcAuth),
	)
	if err != nil {
		return nil, err
	}
	authClient := pb.NewAuthenticatorClient(conn)
	return &AuthenticateGRPC{conn: conn, client: authClient}, nil
}
