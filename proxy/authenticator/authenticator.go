package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"

import (
	"time"
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

// Options contains options for connecting to an authenticate service .
type Options struct {
	// Addr is the location of the authenticate service. Used if InternalAddr is not set.
	Addr string
	Port int
	// InternalAddr is the internal (behind the ingress) address to use when making an
	// authentication connection. If empty, Addr is used.
	InternalAddr string
	// OverrideCertificateName overrides the server name used to verify the hostname on the
	// returned certificates from the server.  gRPC internals also use it to override the virtual
	// hosting name if it is set.
	OverrideCertificateName string
	// Shared secret is used to authenticate a authenticate-client with a authenticate-server.
	SharedSecret string
	// CA specifies the base64 encoded TLS certificate authority to use.
	CA string
	// CAFile specifies the TLS certificate authority file to use.
	CAFile string
}

// New returns a new authenticate service client. Takes a client implementation name as an argument.
// Currently only gRPC is supported and is always returned.
func New(name string, opts *Options) (a Authenticator, err error) {
	return NewGRPC(opts)
}
