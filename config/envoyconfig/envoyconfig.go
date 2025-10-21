// Package envoyconfig contains a Builder for building Envoy configuration from Pomerium configuration.
package envoyconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	"github.com/martinlindhe/base36"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/httputil"
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
	loadBalancerWeight *wrapperspb.UInt32Value
}

// NewEndpoint creates a new Endpoint.
func NewEndpoint(u *url.URL, ts *envoy_config_core_v3.TransportSocket, weight uint32) Endpoint {
	var w *wrapperspb.UInt32Value
	if weight > 0 {
		w = &wrapperspb.UInt32Value{Value: weight}
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
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(connectionBufferLimit),
	}
}

func buildAccessLogs(options *config.Options) []*envoy_config_accesslog_v3.AccessLog {
	lvl := options.ProxyLogLevel
	if lvl == "" {
		lvl = options.LogLevel
	}
	if lvl == "" {
		lvl = config.LogLevelDebug
	}

	switch lvl {
	case config.LogLevelTrace, config.LogLevelDebug, config.LogLevelInfo:
	default:
		// don't log access requests for levels > info
		return nil
	}

	var additionalRequestHeaders []string
	for _, field := range options.AccessLogFields {
		if headerName, ok := log.GetHeaderField(field); ok {
			additionalRequestHeaders = append(additionalRequestHeaders, httputil.CanonicalHeaderKey(headerName))
		}
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
		AdditionalRequestHeadersToLog: additionalRequestHeaders,
	})
	return []*envoy_config_accesslog_v3.AccessLog{{
		Name:       "envoy.access_loggers.http_grpc",
		ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{TypedConfig: tc},
	}}
}

func buildTCPAddress(hostport string, defaultPort uint32) *envoy_config_core_v3.Address {
	return buildAddress(envoy_config_core_v3.SocketAddress_TCP, hostport, defaultPort)
}

func buildUDPAddress(hostport string, defaultPort uint32) *envoy_config_core_v3.Address {
	return buildAddress(envoy_config_core_v3.SocketAddress_UDP, hostport, defaultPort)
}

func buildIPAddressFromURL(src string) (*envoy_config_core_v3.Address, error) {
	u, err := url.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "tcp" && u.Scheme != "udp" {
		return nil, fmt.Errorf("unsupported url scheme: %s", u.Scheme)
	}
	var protocol envoy_config_core_v3.SocketAddress_Protocol
	switch u.Scheme {
	case "tcp":
		protocol = envoy_config_core_v3.SocketAddress_TCP
	case "udp":
		protocol = envoy_config_core_v3.SocketAddress_UDP
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("must include an IP address: %s", src)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("host must be an IP address: %s", host)
	}
	portStr := u.Port()
	if portStr == "" {
		return nil, fmt.Errorf("must include a port: %s", src)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port == 0 {
		return nil, fmt.Errorf("port must be greater than zero: %s", portStr)
	}
	hostport := net.JoinHostPort(host, portStr)
	return buildAddress(protocol, hostport, uint32(port)), nil
}

func buildAddress(protocol envoy_config_core_v3.SocketAddress_Protocol, hostport string, defaultPort uint32) *envoy_config_core_v3.Address {
	host, strport, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		strport = fmt.Sprint(defaultPort)
	}
	port := defaultPort
	if p, err := strconv.ParseUint(strport, 10, 32); err == nil {
		port = uint32(p)
	}
	if host == "" {
		if nettest.SupportsIPv6() {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}

	is4in6 := false
	if addr, err := netip.ParseAddr(host); err == nil {
		is4in6 = addr.Is4In6()
	}

	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{SocketAddress: &envoy_config_core_v3.SocketAddress{
			Protocol:      protocol,
			Address:       host,
			PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: port},
			Ipv4Compat:    host == "::" || is4in6,
		}},
	}
}

var rootCABundle struct {
	sync.Once
	value string
}

func getRootCertificateAuthority(ctx context.Context) (string, error) {
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
			log.Ctx(ctx).Error().Strs("known-locations", knownRootLocations).
				Msgf("no root certificates were found in any of the known locations")
		} else {
			log.Ctx(ctx).Info().Msgf("using %s as the system root certificate authority bundle", rootCABundle.value)
		}
	})
	if rootCABundle.value == "" {
		return "", fmt.Errorf("root certificates not found")
	}
	return rootCABundle.value, nil
}

func getCombinedCertificateAuthority(ctx context.Context, cfg *config.Config) ([]byte, error) {
	rootFile, err := getRootCertificateAuthority(ctx)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := fileutil.CopyFileUpTo(&buf, rootFile, 5<<20); err != nil {
		return nil, fmt.Errorf("error reading root certificates: %w", err)
	}
	buf.WriteRune('\n')

	all, err := cfg.AllCertificateAuthoritiesPEM()
	if err != nil {
		return nil, fmt.Errorf("get all CA: %w", err)
	}
	buf.Write(all)

	return buf.Bytes(), nil
}

func marshalAny(msg proto.Message) *anypb.Any {
	data := new(anypb.Any)
	_ = anypb.MarshalFrom(data, msg, proto.MarshalOptions{
		AllowPartial:  true,
		Deterministic: true,
	})
	return data
}

// parseAddress parses a string address into an envoy address.
func parseAddress(raw string) (*envoy_config_core_v3.Address, error) {
	if host, portstr, err := net.SplitHostPort(raw); err == nil {
		if host == "localhost" {
			host = "127.0.0.1"
		}

		if port, err := strconv.ParseUint(portstr, 10, 32); err == nil {
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
