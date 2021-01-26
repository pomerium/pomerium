package controlplane

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
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

func (srv *Server) buildClusters(options *config.Options) ([]*envoy_config_cluster_v3.Cluster, error) {
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

	controlGRPC, err := srv.buildInternalCluster(options, "pomerium-control-plane-grpc", grpcURL, true)
	if err != nil {
		return nil, err
	}
	controlHTTP, err := srv.buildInternalCluster(options, "pomerium-control-plane-http", httpURL, false)
	if err != nil {
		return nil, err
	}
	authZ, err := srv.buildInternalCluster(options, authzURL.Host, authzURL, true)
	if err != nil {
		return nil, err
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		controlGRPC,
		controlHTTP,
		authZ,
	}

	if config.IsProxy(options.Services) {
		for i, p := range options.GetAllPolicies() {
			policy := p
			if policy.EnvoyOpts == nil {
				policy.EnvoyOpts = newDefaultEnvoyClusterConfig()
			}
			if len(policy.Destinations) > 0 {
				cluster, err := srv.buildPolicyCluster(options, &policy)
				if err != nil {
					return nil, fmt.Errorf("policy #%d: %w", i, err)
				}
				clusters = append(clusters, cluster)
			}
		}
	}

	return clusters, nil
}

func (srv *Server) buildInternalCluster(options *config.Options, name string, dst *url.URL, forceHTTP2 bool) (*envoy_config_cluster_v3.Cluster, error) {
	cluster := newDefaultEnvoyClusterConfig()
	cluster.DnsLookupFamily = config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	endpoints, err := srv.buildInternalEndpoints(options, dst)
	if err != nil {
		return nil, err
	}
	if err := srv.buildCluster(cluster, name, endpoints, forceHTTP2); err != nil {
		return nil, err
	}
	return cluster, nil
}

func (srv *Server) buildPolicyCluster(options *config.Options, policy *config.Policy) (*envoy_config_cluster_v3.Cluster, error) {
	cluster := policy.EnvoyOpts

	name := getPolicyName(policy)
	endpoints, err := srv.buildPolicyEndpoints(policy)
	if err != nil {
		return nil, err
	}

	if cluster.DnsLookupFamily == envoy_config_cluster_v3.Cluster_AUTO {
		cluster.DnsLookupFamily = config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	}

	if policy.EnableGoogleCloudServerlessAuthentication {
		cluster.DnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY
	}

	if err := srv.buildCluster(cluster, name, endpoints, false); err != nil {
		return nil, err
	}

	return cluster, nil
}

func (srv *Server) buildInternalEndpoints(options *config.Options, dst *url.URL) ([]Endpoint, error) {
	var endpoints []Endpoint
	if ts, err := srv.buildInternalTransportSocket(options, dst); err != nil {
		return nil, err
	} else {
		endpoints = append(endpoints, NewEndpoint(dst, ts))
	}
	return endpoints, nil
}

func (srv *Server) buildPolicyEndpoints(policy *config.Policy) ([]Endpoint, error) {
	var endpoints []Endpoint
	for _, dst := range policy.Destinations {
		if ts, err := srv.buildPolicyTransportSocket(policy, dst); err != nil {
			return nil, err
		} else {
			endpoints = append(endpoints, NewEndpoint(dst, ts))
		}
	}
	return endpoints, nil
}

func (srv *Server) buildInternalTransportSocket(options *config.Options, endpoint *url.URL) (*envoy_config_core_v3.TransportSocket, error) {
	if endpoint.Scheme != "https" {
		return nil, nil
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
	}, nil
}

func (srv *Server) buildPolicyTransportSocket(policy *config.Policy, dst *url.URL) (*envoy_config_core_v3.TransportSocket, error) {
	if dst == nil || dst.Scheme != "https" {
		return nil, nil
	}

	vc, err := srv.buildPolicyValidationContext(policy, dst)
	if err != nil {
		return nil, err
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
				ValidationContext: vc,
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
	}, nil
}

func (srv *Server) buildPolicyValidationContext(policy *config.Policy, dst *url.URL) (*envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext, error) {
	if dst == nil {
		return nil, nil
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

	return validationContext, nil
}

func (srv *Server) buildCluster(
	cluster *envoy_config_cluster_v3.Cluster,
	name string,
	endpoints []Endpoint,
	forceHTTP2 bool,
) error {
	if len(endpoints) == 0 {
		return errNoEndpoints
	}

	if cluster.ConnectTimeout == nil {
		cluster.ConnectTimeout = defaultConnectionTimeout
	}
	cluster.RespectDnsTtl = true
	lbEndpoints, err := srv.buildLbEndpoints(endpoints)
	if err != nil {
		return err
	}
	cluster.Name = name
	cluster.LoadAssignment = &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: name,
		Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
			LbEndpoints: lbEndpoints,
		}},
	}
	cluster.TransportSocketMatches, err = srv.buildTransportSocketMatches(endpoints)
	if err != nil {
		return err
	}

	if forceHTTP2 {
		cluster.Http2ProtocolOptions = &envoy_config_core_v3.Http2ProtocolOptions{
			AllowConnect: true,
		}
	}

	// for IPs we use a static discovery type, otherwise we use DNS
	allIP := true
	for _, lbe := range lbEndpoints {
		if net.ParseIP(urlutil.StripPort(lbe.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())) == nil {
			allIP = false
		}
	}
	if allIP {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	} else {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STRICT_DNS}
	}

	return cluster.Validate()
}

func (srv *Server) buildLbEndpoints(endpoints []Endpoint) ([]*envoy_config_endpoint_v3.LbEndpoint, error) {
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
	return lbes, nil
}

func (srv *Server) buildTransportSocketMatches(endpoints []Endpoint) ([]*envoy_config_cluster_v3.Cluster_TransportSocketMatch, error) {
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
	return tsms, nil
}
