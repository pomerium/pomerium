package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// NewGRPC returns a new authenticate service client.
func NewGRPC(opts *Options) (p *AuthenticateGRPC, err error) {
	// gRPC uses a pre-shared secret middleware to establish authentication b/w server and client
	if opts.SharedSecret == "" {
		return nil, errors.New("proxy/authenticator: grpc client requires shared secret")
	}
	grpcAuth := middleware.NewSharedSecretCred(opts.SharedSecret)

	var connAddr string
	if opts.InternalAddr != "" {
		connAddr = opts.InternalAddr
	} else {
		connAddr = opts.Addr
	}
	if connAddr == "" {
		return nil, errors.New("proxy/authenticator: connection address required")
	}
	// no colon exists in the connection string, assume one must be added manually
	if !strings.Contains(connAddr, ":") {
		connAddr = fmt.Sprintf("%s:%d", connAddr, opts.Port)
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
		Str("addr", connAddr).Msgf("proxy/authenticator: grpc connection")
	cert := credentials.NewTLS(&tls.Config{RootCAs: cp})

	// override allowed certificate name string, typically used when doing behind ingress connection
	if opts.OverrideCertificateName != "" {
		err = cert.OverrideServerName(opts.OverrideCertificateName)
		if err != nil {
			return nil, err
		}
	}
	conn, err := grpc.Dial(
		connAddr,
		grpc.WithTransportCredentials(cert),
		grpc.WithPerRPCCredentials(grpcAuth),
	)
	if err != nil {
		return nil, err
	}
	authClient := pb.NewAuthenticatorClient(conn)
	return &AuthenticateGRPC{Conn: conn, client: authClient}, nil
}

// RedeemResponse contains data from a authenticator redeem request.
type RedeemResponse struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	User         string
	Email        string
	Expiry       time.Time
}

// AuthenticateGRPC is a gRPC implementation of an authenticator (authenticate client)
type AuthenticateGRPC struct {
	Conn   *grpc.ClientConn
	client pb.AuthenticatorClient
}

// Redeem makes an RPC call to the authenticate service to creates a session state
// from an encrypted code provided as a result of an oauth2 callback process.
func (a *AuthenticateGRPC) Redeem(code string) (*RedeemResponse, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := a.client.Authenticate(ctx, &pb.AuthenticateRequest{Code: code})
	if err != nil {
		return nil, err
	}
	expiry, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		return nil, err
	}
	return &RedeemResponse{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		IDToken:      r.IdToken,
		User:         r.User,
		Email:        r.Email,
		Expiry:       expiry,
	}, nil
}

// Refresh makes an RPC call to the authenticate service to attempt to refresh the
// user's session. Requires a valid refresh token. Will return an error if the identity provider
// has revoked the session or if the refresh token is no longer valid in this context.
func (a *AuthenticateGRPC) Refresh(refreshToken string) (string, time.Time, error) {
	if refreshToken == "" {
		return "", time.Time{}, errors.New("missing refresh token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := a.client.Refresh(ctx, &pb.RefreshRequest{RefreshToken: refreshToken})
	if err != nil {
		return "", time.Time{}, err
	}

	expiry, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		return "", time.Time{}, err
	}
	return r.AccessToken, expiry, nil
}

// Validate makes an RPC call to the authenticate service to validate the JWT id token;
// does NOT do nonce or revokation validation.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (a *AuthenticateGRPC) Validate(idToken string) (bool, error) {
	if idToken == "" {
		return false, errors.New("missing id token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := a.client.Validate(ctx, &pb.ValidateRequest{IdToken: idToken})
	if err != nil {
		return false, err
	}
	return r.IsValid, nil
}

// Close tears down the ClientConn and all underlying connections.
func (a *AuthenticateGRPC) Close() error {
	return a.Conn.Close()
}
