// Package envoyconfig contains a Builder for building Envoy configuration from Pomerium configuration.
package envoyconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/martinlindhe/base36"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

var (
	errNoEndpoints           = errors.New("cluster must have endpoints")
	defaultConnectionTimeout = durationpb.New(time.Second * 10)
)

// An Endpoint is a URL with its corresponding Transport Socket.
type Endpoint struct {
	url                url.URL
	transportSocket    *envoy_config_core_v3.TransportSocket
	loadBalancerWeight *wrappers.UInt32Value
}

// NewEndpoint creates a new Endpoint.
func NewEndpoint(u *url.URL, ts *envoy_config_core_v3.TransportSocket, weight uint32) Endpoint {
	var w *wrappers.UInt32Value
	if weight > 0 {
		w = &wrappers.UInt32Value{Value: weight}
	}
	return Endpoint{url: *u, transportSocket: ts, loadBalancerWeight: w}
}

// TransportSocketName return the name for this endpoint.
func (e Endpoint) TransportSocketName() string {
	if e.transportSocket == nil {
		return ""
	}
	h := cryptutil.HashProto(e.transportSocket)
	return "ts-" + base36.EncodeBytes(h)
}

// newDefaultEnvoyClusterConfig creates envoy cluster with certain default values
func newDefaultEnvoyClusterConfig() *envoy_config_cluster_v3.Cluster {
	return &envoy_config_cluster_v3.Cluster{
		ConnectTimeout:                defaultConnectionTimeout,
		RespectDnsTtl:                 true,
		DnsLookupFamily:               envoy_config_cluster_v3.Cluster_AUTO,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(connectionBufferLimit),
	}
}

func buildAccessLogs(options *config.Options) []*envoy_config_accesslog_v3.AccessLog {
	lvl := options.ProxyLogLevel
	if lvl == "" {
		lvl = options.LogLevel
	}
	if lvl == "" {
		lvl = "debug"
	}

	switch lvl {
	case "trace", "debug", "info":
	default:
		// don't log access requests for levels > info
		return nil
	}

	tc := marshalAny(&envoy_extensions_access_loggers_grpc_v3.HttpGrpcAccessLogConfig{
		CommonConfig: &envoy_extensions_access_loggers_grpc_v3.CommonGrpcAccessLogConfig{
			LogName: "ingress-http",
			GrpcService: &envoy_config_core_v3.GrpcService{
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "pomerium-control-plane-grpc",
					},
				},
			},
			TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
		},
	})
	return []*envoy_config_accesslog_v3.AccessLog{{
		Name:       "envoy.access_loggers.http_grpc",
		ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{TypedConfig: tc},
	}}
}

func buildAddress(hostport string, defaultPort int) *envoy_config_core_v3.Address {
	host, strport, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		strport = fmt.Sprint(defaultPort)
	}
	port, err := strconv.Atoi(strport)
	if err != nil {
		port = defaultPort
	}
	if host == "" {
		if nettest.SupportsIPv6() {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}
	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{SocketAddress: &envoy_config_core_v3.SocketAddress{
			Address:       host,
			PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: uint32(port)},
			Ipv4Compat:    true,
		}},
	}
}

func (b *Builder) envoyTLSCertificateFromGoTLSCertificate(
	ctx context.Context,
	cert *tls.Certificate,
) *envoy_extensions_transport_sockets_tls_v3.TlsCertificate {
	envoyCert := &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{}
	var chain bytes.Buffer
	for _, cbs := range cert.Certificate {
		_ = pem.Encode(&chain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cbs,
		})
	}
	envoyCert.CertificateChain = b.filemgr.BytesDataSource("tls-crt.pem", chain.Bytes())
	if cert.OCSPStaple != nil {
		envoyCert.OcspStaple = b.filemgr.BytesDataSource("ocsp-staple", cert.OCSPStaple)
	}
	if bs, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		envoyCert.PrivateKey = b.filemgr.BytesDataSource("tls-key.pem", pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: bs,
			},
		))
	} else {
		log.Warn(ctx).Err(err).Msg("failed to marshal private key for tls config")
	}
	for _, scts := range cert.SignedCertificateTimestamps {
		envoyCert.SignedCertificateTimestamp = append(envoyCert.SignedCertificateTimestamp,
			b.filemgr.BytesDataSource("signed-certificate-timestamp", scts))
	}
	return envoyCert
}

var rootCABundle struct {
	sync.Once
	value string
}

func getRootCertificateAuthority() (string, error) {
	rootCABundle.Do(func() {
		// from https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl#arch-overview-ssl-enabling-verification
		knownRootLocations := []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/ca-bundle.pem",
			"/usr/local/etc/ssl/cert.pem",
			"/etc/ssl/cert.pem",
		}
		for _, path := range knownRootLocations {
			if _, err := os.Stat(path); err == nil {
				rootCABundle.value = path
				break
			}
		}
		if rootCABundle.value == "" {
			log.Error(context.TODO()).Strs("known-locations", knownRootLocations).
				Msgf("no root certificates were found in any of the known locations")
		} else {
			log.Info(context.TODO()).Msgf("using %s as the system root certificate authority bundle", rootCABundle.value)
		}
	})
	if rootCABundle.value == "" {
		return "", fmt.Errorf("root certificates not found")
	}
	return rootCABundle.value, nil
}

func getCombinedCertificateAuthority(customCA, customCAFile string) ([]byte, error) {
	rootFile, err := getRootCertificateAuthority()
	if err != nil {
		return nil, err
	}

	combined, err := os.ReadFile(rootFile)
	if err != nil {
		return nil, fmt.Errorf("error reading root certificates: %w", err)
	}

	if customCA != "" {
		bs, err := base64.StdEncoding.DecodeString(customCA)
		if err != nil {
			return nil, err
		}
		combined = append(combined, '\n')
		combined = append(combined, bs...)
	}

	if customCAFile != "" {
		bs, err := os.ReadFile(customCAFile)
		if err != nil {
			return nil, err
		}
		combined = append(combined, '\n')
		combined = append(combined, bs...)
	}

	return combined, nil
}

func marshalAny(msg proto.Message) *anypb.Any {
	any := new(anypb.Any)
	_ = anypb.MarshalFrom(any, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return any
}

// parseAddress parses a string address into an envoy address.
func parseAddress(raw string) (*envoy_config_core_v3.Address, error) {
	if host, portstr, err := net.SplitHostPort(raw); err == nil {
		if host == "localhost" {
			host = "127.0.0.1"
		}

		if port, err := strconv.Atoi(portstr); err == nil {
			return &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: host,
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: uint32(port),
						},
					},
				},
			}, nil
		}
	}
	return nil, fmt.Errorf("unknown address format: %s", raw)
}
