package controlplane

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	clusterTypeURL  = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	listenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"
)

func (srv *Server) buildDiscoveryResources() (map[string][]*envoy_service_discovery_v3.Resource, error) {
	resources := map[string][]*envoy_service_discovery_v3.Resource{}
	cfg := srv.currentConfig.Load()

	clusters, err := srv.buildClusters(cfg.Options)
	if err != nil {
		return nil, err
	}
	for _, cluster := range clusters {
		any, _ := anypb.New(cluster)
		resources[clusterTypeURL] = append(resources[clusterTypeURL], &envoy_service_discovery_v3.Resource{
			Name:     cluster.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(cluster)),
			Resource: any,
		})
	}

	listeners, err := srv.buildListeners(cfg.Config)
	if err != nil {
		return nil, err
	}
	for _, listener := range listeners {
		any, _ := anypb.New(listener)
		resources[listenerTypeURL] = append(resources[listenerTypeURL], &envoy_service_discovery_v3.Resource{
			Name:     listener.Name,
			Version:  hex.EncodeToString(cryptutil.HashProto(listener)),
			Resource: any,
		})
	}
	return resources, nil
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

func (srv *Server) envoyTLSCertificateFromGoTLSCertificate(cert *tls.Certificate) *envoy_extensions_transport_sockets_tls_v3.TlsCertificate {
	envoyCert := &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{}
	var chain bytes.Buffer
	for _, cbs := range cert.Certificate {
		_ = pem.Encode(&chain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cbs,
		})
	}
	envoyCert.CertificateChain = srv.filemgr.BytesDataSource("tls-crt.pem", chain.Bytes())
	if cert.OCSPStaple != nil {
		envoyCert.OcspStaple = srv.filemgr.BytesDataSource("ocsp-staple", cert.OCSPStaple)
	}
	if bs, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		envoyCert.PrivateKey = srv.filemgr.BytesDataSource("tls-key.pem", pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: bs,
			},
		))
	} else {
		log.Warn().Err(err).Msg("failed to marshal private key for tls config")
	}
	for _, scts := range cert.SignedCertificateTimestamps {
		envoyCert.SignedCertificateTimestamp = append(envoyCert.SignedCertificateTimestamp,
			srv.filemgr.BytesDataSource("signed-certificate-timestamp", scts))
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
			log.Error().Strs("known-locations", knownRootLocations).
				Msgf("no root certificates were found in any of the known locations")
		} else {
			log.Info().Msgf("using %s as the system root certificate authority bundle", rootCABundle.value)
		}
	})
	if rootCABundle.value == "" {
		return "", fmt.Errorf("root certificates not found")
	}
	return rootCABundle.value, nil
}

func marshalAny(msg proto.Message) *anypb.Any {
	any := new(anypb.Any)
	_ = anypb.MarshalFrom(any, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return any
}
