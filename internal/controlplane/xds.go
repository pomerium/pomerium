package controlplane

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	xxhash "github.com/cespare/xxhash/v2"
	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"golang.org/x/net/nettest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

func (srv *Server) buildDiscoveryResponse(version string, typeURL string, options *config.Options) (*envoy_service_discovery_v3.DiscoveryResponse, error) {
	switch typeURL {
	case "type.googleapis.com/envoy.config.listener.v3.Listener":
		listeners := buildListeners(options)
		anys := make([]*any.Any, len(listeners))
		for i, listener := range listeners {
			a, err := ptypes.MarshalAny(listener)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "error marshaling type to any: %v", err)
			}
			anys[i] = a
		}
		return &envoy_service_discovery_v3.DiscoveryResponse{
			VersionInfo: version,
			Resources:   anys,
			TypeUrl:     typeURL,
		}, nil
	case "type.googleapis.com/envoy.config.cluster.v3.Cluster":
		clusters := srv.buildClusters(options)
		anys := make([]*any.Any, len(clusters))
		for i, cluster := range clusters {
			a, err := ptypes.MarshalAny(cluster)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "error marshaling type to any: %v", err)
			}
			anys[i] = a
		}
		return &envoy_service_discovery_v3.DiscoveryResponse{
			VersionInfo: version,
			Resources:   anys,
			TypeUrl:     typeURL,
		}, nil
	default:
		return nil, status.Errorf(codes.Internal, "received request for unknown discovery request type: %s", typeURL)
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

	tc, _ := ptypes.MarshalAny(&envoy_extensions_access_loggers_grpc_v3.HttpGrpcAccessLogConfig{
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

func inlineBytes(bs []byte) *envoy_config_core_v3.DataSource {
	return &envoy_config_core_v3.DataSource{
		Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
			InlineBytes: bs,
		},
	}
}

func inlineBytesAsFilename(name string, bs []byte) *envoy_config_core_v3.DataSource {
	ext := filepath.Ext(name)
	name = fmt.Sprintf("%s-%x%s", name[:len(name)-len(ext)], xxhash.Sum64(bs), ext)

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = filepath.Join(os.TempDir())
	}
	cacheDir = filepath.Join(cacheDir, "pomerium", "envoy", "files")
	if err = os.MkdirAll(cacheDir, 0755); err != nil {
		log.Error().Err(err).Msg("error creating cache directory, falling back to inline bytes")
		return inlineBytes(bs)
	}

	fp := filepath.Join(cacheDir, name)
	if _, err = os.Stat(fp); os.IsNotExist(err) {
		err = ioutil.WriteFile(fp, bs, 0600)
		if err != nil {
			log.Error().Err(err).Msg("error writing cache file, falling back to inline bytes")
			return inlineBytes(bs)
		}
	} else if err != nil {
		log.Error().Err(err).Msg("error reading cache file, falling back to inline bytes")
		return inlineBytes(bs)
	}

	return inlineFilename(fp)
}

func inlineFilename(name string) *envoy_config_core_v3.DataSource {
	return &envoy_config_core_v3.DataSource{
		Specifier: &envoy_config_core_v3.DataSource_Filename{
			Filename: name,
		},
	}
}

func getPolicyName(policy *config.Policy) string {
	return fmt.Sprintf("policy-%x", policy.RouteID())
}

func envoyTLSCertificateFromGoTLSCertificate(cert *tls.Certificate) *envoy_extensions_transport_sockets_tls_v3.TlsCertificate {
	envoyCert := &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{}
	var chain bytes.Buffer
	for _, cbs := range cert.Certificate {
		_ = pem.Encode(&chain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cbs,
		})
	}
	envoyCert.CertificateChain = inlineBytesAsFilename("tls-crt.pem", chain.Bytes())
	if cert.OCSPStaple != nil {
		envoyCert.OcspStaple = inlineBytes(cert.OCSPStaple)
	}
	if bs, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		envoyCert.PrivateKey = inlineBytesAsFilename("tls-key.pem", pem.EncodeToMemory(
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
			inlineBytes(scts))
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
