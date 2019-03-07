package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
)

const defaultGRPCPort = 443

// Options contains options for connecting to a pomerium rpc service.
type Options struct {
	// Addr is the location of the authenticate service.  e.g. "service.corp.example:8443"
	Addr string
	// InternalAddr is the internal (behind the ingress) address to use when
	// making a connection. If empty, Addr is used.
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

// NewGRPCClientConn returns a new gRPC pomerium service client connection.
func NewGRPCClientConn(opts *Options) (*grpc.ClientConn, error) {
	// gRPC uses a pre-shared secret middleware to establish authentication b/w server and client
	if opts.SharedSecret == "" {
		return nil, errors.New("proxy/clients: grpc client requires shared secret")
	}
	grpcAuth := middleware.NewSharedSecretCred(opts.SharedSecret)

	var connAddr string
	if opts.InternalAddr != "" {
		connAddr = opts.InternalAddr
	} else {
		connAddr = opts.Addr
	}
	if connAddr == "" {
		return nil, errors.New("proxy/clients: connection address required")
	}
	// no colon exists in the connection string, assume one must be added manually
	if !strings.Contains(connAddr, ":") {
		connAddr = fmt.Sprintf("%s:%d", connAddr, defaultGRPCPort)
	}

	var cp *x509.CertPool
	if opts.CA != "" || opts.CAFile != "" {
		cp = x509.NewCertPool()
		var ca []byte
		var err error
		if opts.CA != "" {
			ca, err = base64.StdEncoding.DecodeString(opts.CA)
			if err != nil {
				return nil, fmt.Errorf("failed to decode certificate authority: %v", err)
			}
		} else {
			ca, err = ioutil.ReadFile(opts.CAFile)
			if err != nil {
				return nil, fmt.Errorf("certificate authority file %v not readable: %v", opts.CAFile, err)
			}
		}
		if ok := cp.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("failed to append CA cert to certPool")
		}
	} else {
		newCp, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		cp = newCp
	}

	log.Info().
		Str("OverrideCertificateName", opts.OverrideCertificateName).
		Str("addr", connAddr).Msgf("proxy/clients: grpc connection")
	cert := credentials.NewTLS(&tls.Config{RootCAs: cp})

	// override allowed certificate name string, typically used when doing behind ingress connection
	if opts.OverrideCertificateName != "" {
		err := cert.OverrideServerName(opts.OverrideCertificateName)
		if err != nil {
			return nil, err
		}
	}
	return grpc.Dial(
		connAddr,
		grpc.WithTransportCredentials(cert),
		grpc.WithPerRPCCredentials(grpcAuth),
	)
}
