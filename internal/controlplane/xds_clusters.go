package controlplane

import (
	"encoding/base64"
	"net"
	"net/url"
	"strings"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// recommended defaults: https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge
const (
	connectionBufferLimit            uint32 = 32 * 1024
	maxConcurrentStreams             uint32 = 100
	initialStreamWindowSizeLimit     uint32 = 64 * 1024
	initialConnectionWindowSizeLimit uint32 = 1 * 1024 * 1024
)

func (srv *Server) buildClusters(options *config.Options) []*envoy_config_cluster_v3.Cluster {
	grpcURL := &url.URL{
		Scheme: "http",
		Host:   srv.GRPCListener.Addr().String(),
	}
	httpURL := &url.URL{
		Scheme: "http",
		Host:   srv.HTTPListener.Addr().String(),
	}
	authzURL := &url.URL{
		Scheme: options.GetAuthorizeURL().Scheme,
		Host:   options.GetAuthorizeURL().Host,
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		buildInternalCluster(options, "pomerium-control-plane-grpc", grpcURL, true),
		buildInternalCluster(options, "pomerium-control-plane-http", httpURL, false),
	}

	clusters = append(clusters, buildInternalCluster(options, authzURL.Host, authzURL, true))

	if config.IsProxy(options.Services) {
		for i := range options.Policies {
			policy := options.Policies[i]
			clusters = append(clusters, buildPolicyCluster(options, &policy))
		}
	}

	return clusters
}

func buildInternalCluster(options *config.Options, name string, endpoint *url.URL, forceHTTP2 bool) *envoy_config_cluster_v3.Cluster {
	dnsLookupFamily := config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	return buildCluster(name, endpoint, buildInternalTransportSocket(options, endpoint), forceHTTP2, dnsLookupFamily)
}

func buildPolicyCluster(options *config.Options, policy *config.Policy) *envoy_config_cluster_v3.Cluster {
	name := getPolicyName(policy)
	dnsLookupFamily := config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	if policy.EnableGoogleCloudServerlessAuthentication {
		dnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY
	}
	return buildCluster(name, policy.Destination, buildPolicyTransportSocket(policy), false, dnsLookupFamily)
}

func buildInternalTransportSocket(options *config.Options, endpoint *url.URL) *envoy_config_core_v3.TransportSocket {
	if endpoint.Scheme != "https" {
		return nil
	}
	sni := endpoint.Hostname()
	if options.OverrideCertificateName != "" {
		sni = options.OverrideCertificateName
	}
	validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		MatchSubjectAltNames: []*envoy_type_matcher_v3.StringMatcher{{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: sni,
			},
		}},
	}
	if options.CAFile != "" {
		validationContext.TrustedCa = inlineFilename(options.CAFile)
	} else if options.CA != "" {
		bs, err := base64.StdEncoding.DecodeString(options.CA)
		if err != nil {
			log.Error().Err(err).Msg("invalid custom CA certificate")
		}
		validationContext.TrustedCa = inlineBytesAsFilename("custom-ca.pem", bs)
	} else {
		rootCA, err := getRootCertificateAuthority()
		if err != nil {
			log.Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
		} else {
			validationContext.TrustedCa = inlineFilename(rootCA)
		}
	}
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			AlpnProtocols: []string{"h2", "http/1.1"},
			ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: validationContext,
			},
		},
		Sni: sni,
	}
	tlsConfig, _ := ptypes.MarshalAny(tlsContext)
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: tlsConfig,
		},
	}
}

func buildPolicyTransportSocket(policy *config.Policy) *envoy_config_core_v3.TransportSocket {
	if policy.Destination.Scheme != "https" {
		return nil
	}

	sni := policy.Destination.Hostname()
	if policy.TLSServerName != "" {
		sni = policy.TLSServerName
	}
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams: &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
				EcdhCurves: []string{
					"X25519",
					"P-256",
					"P-384",
					"P-521",
				},
			},
			AlpnProtocols: []string{"http/1.1"},
			ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: buildPolicyValidationContext(policy),
			},
		},
		Sni: sni,
	}
	if policy.ClientCertificate != nil {
		tlsContext.CommonTlsContext.TlsCertificates = append(tlsContext.CommonTlsContext.TlsCertificates,
			envoyTLSCertificateFromGoTLSCertificate(policy.ClientCertificate))
	}

	tlsConfig, _ := ptypes.MarshalAny(tlsContext)
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: tlsConfig,
		},
	}
}

func buildPolicyValidationContext(policy *config.Policy) *envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext {
	sni := policy.Destination.Hostname()
	if policy.TLSServerName != "" {
		sni = policy.TLSServerName
	}
	validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		MatchSubjectAltNames: []*envoy_type_matcher_v3.StringMatcher{{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: sni,
			},
		}},
	}
	if policy.TLSCustomCAFile != "" {
		validationContext.TrustedCa = inlineFilename(policy.TLSCustomCAFile)
	} else if policy.TLSCustomCA != "" {
		bs, err := base64.StdEncoding.DecodeString(policy.TLSCustomCA)
		if err != nil {
			log.Error().Err(err).Msg("invalid custom CA certificate")
		}
		validationContext.TrustedCa = inlineBytesAsFilename("custom-ca.pem", bs)
	} else {
		rootCA, err := getRootCertificateAuthority()
		if err != nil {
			log.Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
		} else {
			validationContext.TrustedCa = inlineFilename(rootCA)
		}
	}

	if policy.TLSSkipVerify {
		validationContext.TrustChainVerification = envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED
	}

	return validationContext
}

func buildCluster(
	name string,
	endpoint *url.URL,
	transportSocket *envoy_config_core_v3.TransportSocket,
	forceHTTP2 bool,
	dnsLookupFamily envoy_config_cluster_v3.Cluster_DnsLookupFamily,
) *envoy_config_cluster_v3.Cluster {
	defaultPort := 80
	if transportSocket != nil && transportSocket.Name == "tls" {
		defaultPort = 443
	}

	if endpoint.Hostname() == "localhost" {
		u := new(url.URL)
		*u = *endpoint
		u.Host = strings.Replace(endpoint.Host, "localhost", "127.0.0.1", -1)
		endpoint = u
	}

	cluster := &envoy_config_cluster_v3.Cluster{
		Name:           name,
		ConnectTimeout: ptypes.DurationProto(time.Second * 10),
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
				LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
					HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
						Endpoint: &envoy_config_endpoint_v3.Endpoint{
							Address: buildAddress(endpoint.Host, defaultPort),
						},
					},
				}},
			}},
		},
		RespectDnsTtl:                 true,
		TransportSocket:               transportSocket,
		DnsLookupFamily:               dnsLookupFamily,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(connectionBufferLimit),
	}

	if forceHTTP2 {
		any, _ := anypb.New(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
							AllowConnect:                true,
							InitialStreamWindowSize:     wrapperspb.UInt32(initialStreamWindowSizeLimit),
							InitialConnectionWindowSize: wrapperspb.UInt32(initialConnectionWindowSizeLimit),
						},
					},
				},
			},
		})
		cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": any,
		}
	}

	// for IPs we use a static discovery type, otherwise we use DNS
	if net.ParseIP(urlutil.StripPort(endpoint.Host)) != nil {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	} else {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STRICT_DNS}
	}

	return cluster
}
