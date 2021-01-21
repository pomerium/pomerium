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
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/martinlindhe/base36"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// An Endpoint is a URL with its corresponding Transport Socket.
type Endpoint struct {
	url             *url.URL
	transportSocket *envoy_config_core_v3.TransportSocket
}

// NewEndpoint creates a new Endpoint.
func NewEndpoint(u *url.URL, ts *envoy_config_core_v3.TransportSocket) Endpoint {
	return Endpoint{url: u, transportSocket: ts}
}

// TransportSocketName return the name for this endpoint.
func (e Endpoint) TransportSocketName() string {
	if e.transportSocket == nil {
		return ""
	}
	h := cryptutil.HashProto(e.transportSocket)
	return "ts-" + base36.EncodeBytes(h)
}

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
		srv.buildInternalCluster(options, "pomerium-control-plane-grpc", grpcURL, true),
		srv.buildInternalCluster(options, "pomerium-control-plane-http", httpURL, false),
	}

	clusters = append(clusters, srv.buildInternalCluster(options, authzURL.Host, authzURL, true))

	if config.IsProxy(options.Services) {
		for i := range options.Policies {
			policy := options.Policies[i]
			if len(policy.Destinations) > 0 {
				clusters = append(clusters, srv.buildPolicyCluster(options, &policy))
			}
		}
	}

	return clusters
}

func (srv *Server) buildInternalCluster(options *config.Options, name string, dst *url.URL, forceHTTP2 bool) *envoy_config_cluster_v3.Cluster {
	endpoints := []Endpoint{NewEndpoint(dst, srv.buildInternalTransportSocket(options, dst))}
	dnsLookupFamily := config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	return buildCluster(name, endpoints, forceHTTP2, dnsLookupFamily, nil, nil)
}

func (srv *Server) buildPolicyCluster(options *config.Options, policy *config.Policy) *envoy_config_cluster_v3.Cluster {
	name := getPolicyName(policy)
	endpoints := srv.buildPolicyEndpoints(policy)
	dnsLookupFamily := config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	if policy.EnableGoogleCloudServerlessAuthentication {
		dnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY
	}
	outlierDetection := (*envoy_config_cluster_v3.OutlierDetection)(policy.OutlierDetection)
	return buildCluster(name, endpoints, false, dnsLookupFamily, outlierDetection, policy.HealthCheck)
}

func (srv *Server) buildPolicyEndpoints(policy *config.Policy) []Endpoint {
	var endpoints []Endpoint
	for _, dst := range policy.Destinations {
		endpoints = append(endpoints, NewEndpoint(dst, srv.buildPolicyTransportSocket(policy, dst)))
	}
	return endpoints
}

func (srv *Server) buildInternalTransportSocket(options *config.Options, endpoint *url.URL) *envoy_config_core_v3.TransportSocket {
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
		validationContext.TrustedCa = srv.filemgr.FileDataSource(options.CAFile)
	} else if options.CA != "" {
		bs, err := base64.StdEncoding.DecodeString(options.CA)
		if err != nil {
			log.Error().Err(err).Msg("invalid custom CA certificate")
		}
		validationContext.TrustedCa = srv.filemgr.BytesDataSource("custom-ca.pem", bs)
	} else {
		rootCA, err := getRootCertificateAuthority()
		if err != nil {
			log.Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
		} else {
			validationContext.TrustedCa = srv.filemgr.FileDataSource(rootCA)
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
	tlsConfig := marshalAny(tlsContext)
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: tlsConfig,
		},
	}
}

func (srv *Server) buildPolicyTransportSocket(policy *config.Policy, dst *url.URL) *envoy_config_core_v3.TransportSocket {
	if dst == nil || dst.Scheme != "https" {
		return nil
	}

	sni := dst.Hostname()
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
				ValidationContext: srv.buildPolicyValidationContext(policy, dst),
			},
		},
		Sni: sni,
	}
	if policy.ClientCertificate != nil {
		tlsContext.CommonTlsContext.TlsCertificates = append(tlsContext.CommonTlsContext.TlsCertificates,
			srv.envoyTLSCertificateFromGoTLSCertificate(policy.ClientCertificate))
	}

	tlsConfig := marshalAny(tlsContext)
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: tlsConfig,
		},
	}
}

func (srv *Server) buildPolicyValidationContext(policy *config.Policy, dst *url.URL) *envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext {
	if dst == nil {
		return nil
	}

	sni := dst.Hostname()
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
		validationContext.TrustedCa = srv.filemgr.FileDataSource(policy.TLSCustomCAFile)
	} else if policy.TLSCustomCA != "" {
		bs, err := base64.StdEncoding.DecodeString(policy.TLSCustomCA)
		if err != nil {
			log.Error().Err(err).Msg("invalid custom CA certificate")
		}
		validationContext.TrustedCa = srv.filemgr.BytesDataSource("custom-ca.pem", bs)
	} else {
		rootCA, err := getRootCertificateAuthority()
		if err != nil {
			log.Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
		} else {
			validationContext.TrustedCa = srv.filemgr.FileDataSource(rootCA)
		}
	}

	if policy.TLSSkipVerify {
		validationContext.TrustChainVerification = envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED
	}

	return validationContext
}

func buildCluster(
	name string,
	endpoints []Endpoint,
	forceHTTP2 bool,
	dnsLookupFamily envoy_config_cluster_v3.Cluster_DnsLookupFamily,
	outlierDetection *envoy_config_cluster_v3.OutlierDetection,
	healthCheck *envoy_config_core_v3.HealthCheck,
) *envoy_config_cluster_v3.Cluster {
	if len(endpoints) == 0 {
		return nil
	}

	lbEndpoints := buildLbEndpoints(endpoints)
	cluster := &envoy_config_cluster_v3.Cluster{
		Name:           name,
		ConnectTimeout: ptypes.DurationProto(time.Second * 10),
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
				LbEndpoints: lbEndpoints,
			}},
		},
		RespectDnsTtl:          true,
		TransportSocketMatches: buildTransportSocketMatches(endpoints),
		DnsLookupFamily:        dnsLookupFamily,
		OutlierDetection:       outlierDetection,
	}

	if healthCheck != nil {
		cluster.HealthChecks = append(cluster.HealthChecks, healthCheck)
	}

	if forceHTTP2 {
		cluster.Http2ProtocolOptions = &envoy_config_core_v3.Http2ProtocolOptions{
			AllowConnect: true,
		}
	}

	// for IPs we use a static discovery type, otherwise we use DNS
	isIP := false
	for _, lbe := range lbEndpoints {
		if net.ParseIP(urlutil.StripPort(lbe.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())) != nil {
			isIP = true
		}
	}
	if isIP {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	} else {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STRICT_DNS}
	}

	return cluster
}

func buildLbEndpoints(endpoints []Endpoint) []*envoy_config_endpoint_v3.LbEndpoint {
	var lbes []*envoy_config_endpoint_v3.LbEndpoint
	for _, e := range endpoints {
		defaultPort := 80
		if e.transportSocket != nil && e.transportSocket.Name == "tls" {
			defaultPort = 443
		}

		u := e.url
		if e.url.Hostname() == "localhost" {
			u = new(url.URL)
			*u = *e.url
			u.Host = strings.Replace(e.url.Host, "localhost", "127.0.0.1", -1)
		}

		lbe := &envoy_config_endpoint_v3.LbEndpoint{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: buildAddress(u.Host, defaultPort),
				},
			},
		}

		if e.transportSocket != nil {
			lbe.Metadata = &envoy_config_core_v3.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					"envoy.transport_socket_match": {
						Fields: map[string]*structpb.Value{
							e.TransportSocketName(): structpb.NewBoolValue(true),
						},
					},
				},
			}
		}
		lbes = append(lbes, lbe)
	}
	return lbes
}

func buildTransportSocketMatches(endpoints []Endpoint) []*envoy_config_cluster_v3.Cluster_TransportSocketMatch {
	var tsms []*envoy_config_cluster_v3.Cluster_TransportSocketMatch
	seen := map[string]struct{}{}
	for _, e := range endpoints {
		if e.transportSocket == nil {
			continue
		}

		// only add unique transport sockets
		nm := e.TransportSocketName()
		if _, ok := seen[nm]; ok {
			continue
		}
		seen[nm] = struct{}{}

		tsms = append(tsms, &envoy_config_cluster_v3.Cluster_TransportSocketMatch{
			Name: nm,
			Match: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					nm: structpb.NewBoolValue(true),
				},
			},
			TransportSocket: e.transportSocket,
		})
	}
	return tsms
}
