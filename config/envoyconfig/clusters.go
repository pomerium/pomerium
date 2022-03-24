package envoyconfig

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// BuildClusters builds envoy clusters from the given config.
func (b *Builder) BuildClusters(ctx context.Context, cfg *config.Config) ([]*envoy_config_cluster_v3.Cluster, error) {
	grpcURL := &url.URL{
		Scheme: "http",
		Host:   b.localGRPCAddress,
	}
	httpURL := &url.URL{
		Scheme: "http",
		Host:   b.localHTTPAddress,
	}
	authorizeURLs, err := cfg.Options.GetInternalAuthorizeURLs()
	if err != nil {
		return nil, err
	}
	databrokerURLs, err := cfg.Options.GetDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	controlGRPC, err := b.buildInternalCluster(ctx, cfg.Options, "pomerium-control-plane-grpc", []*url.URL{grpcURL}, upstreamProtocolHTTP2)
	if err != nil {
		return nil, err
	}

	controlHTTP, err := b.buildInternalCluster(ctx, cfg.Options, "pomerium-control-plane-http", []*url.URL{httpURL}, upstreamProtocolAuto)
	if err != nil {
		return nil, err
	}

	authorizeCluster, err := b.buildInternalCluster(ctx, cfg.Options, "pomerium-authorize", authorizeURLs, upstreamProtocolHTTP2)
	if err != nil {
		return nil, err
	}
	if len(authorizeURLs) > 1 {
		authorizeCluster.HealthChecks = grpcHealthChecks("pomerium-authorize")
		authorizeCluster.OutlierDetection = grpcAuthorizeOutlierDetection()
	}

	databrokerCluster, err := b.buildInternalCluster(ctx, cfg.Options, "pomerium-databroker", databrokerURLs, upstreamProtocolHTTP2)
	if err != nil {
		return nil, err
	}
	if len(databrokerURLs) > 1 {
		authorizeCluster.HealthChecks = grpcHealthChecks("pomerium-databroker")
		authorizeCluster.OutlierDetection = grpcAuthorizeOutlierDetection()
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		controlGRPC,
		controlHTTP,
		authorizeCluster,
		databrokerCluster,
	}

	tracingCluster, err := buildTracingCluster(cfg.Options)
	if err != nil {
		return nil, err
	} else if tracingCluster != nil {
		clusters = append(clusters, tracingCluster)
	}

	if config.IsProxy(cfg.Options.Services) {
		for i, p := range cfg.Options.GetAllPolicies() {
			policy := p
			if policy.EnvoyOpts == nil {
				policy.EnvoyOpts = newDefaultEnvoyClusterConfig()
			}
			if len(policy.To) > 0 {
				cluster, err := b.buildPolicyCluster(ctx, cfg.Options, &policy)
				if err != nil {
					return nil, fmt.Errorf("policy #%d: %w", i, err)
				}
				clusters = append(clusters, cluster)
			}
		}
	}

	if err = validateClusters(clusters); err != nil {
		return nil, err
	}

	return clusters, nil
}

func (b *Builder) buildInternalCluster(
	ctx context.Context,
	options *config.Options,
	name string,
	dsts []*url.URL,
	upstreamProtocol upstreamProtocolConfig,
) (*envoy_config_cluster_v3.Cluster, error) {
	cluster := newDefaultEnvoyClusterConfig()
	cluster.DnsLookupFamily = config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	var endpoints []Endpoint
	for _, dst := range dsts {
		ts, err := b.buildInternalTransportSocket(ctx, options, dst)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, NewEndpoint(dst, ts, 1))
	}
	if err := b.buildCluster(cluster, name, endpoints, upstreamProtocol); err != nil {
		return nil, err
	}

	return cluster, nil
}

func (b *Builder) buildPolicyCluster(ctx context.Context, options *config.Options, policy *config.Policy) (*envoy_config_cluster_v3.Cluster, error) {
	cluster := new(envoy_config_cluster_v3.Cluster)
	proto.Merge(cluster, policy.EnvoyOpts)

	if options.EnvoyBindConfigFreebind.IsSet() || options.EnvoyBindConfigSourceAddress != "" {
		cluster.UpstreamBindConfig = new(envoy_config_core_v3.BindConfig)
		if options.EnvoyBindConfigFreebind.IsSet() {
			cluster.UpstreamBindConfig.Freebind = wrapperspb.Bool(options.EnvoyBindConfigFreebind.Bool)
		}
		if options.EnvoyBindConfigSourceAddress != "" {
			cluster.UpstreamBindConfig.SourceAddress = &envoy_config_core_v3.SocketAddress{
				Address: options.EnvoyBindConfigSourceAddress,
				PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
					PortValue: 0,
				},
			}
		} else {
			cluster.UpstreamBindConfig.SourceAddress = &envoy_config_core_v3.SocketAddress{
				Address: "0.0.0.0",
				PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
					PortValue: 0,
				},
			}
		}
	}

	cluster.AltStatName = getClusterStatsName(policy)
	upstreamProtocol := getUpstreamProtocolForPolicy(ctx, policy)

	name := getClusterID(policy)
	endpoints, err := b.buildPolicyEndpoints(ctx, options, policy)
	if err != nil {
		return nil, err
	}

	if cluster.DnsLookupFamily == envoy_config_cluster_v3.Cluster_AUTO {
		cluster.DnsLookupFamily = config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	}

	if policy.EnableGoogleCloudServerlessAuthentication {
		cluster.DnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY
	}

	if err := b.buildCluster(cluster, name, endpoints, upstreamProtocol); err != nil {
		return nil, err
	}

	return cluster, nil
}

func (b *Builder) buildPolicyEndpoints(
	ctx context.Context,
	options *config.Options,
	policy *config.Policy,
) ([]Endpoint, error) {
	var endpoints []Endpoint
	for _, dst := range policy.To {
		ts, err := b.buildPolicyTransportSocket(ctx, options, policy, dst.URL)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, NewEndpoint(&dst.URL, ts, dst.LbWeight))
	}
	return endpoints, nil
}

func (b *Builder) buildInternalTransportSocket(
	ctx context.Context,
	options *config.Options,
	endpoint *url.URL,
) (*envoy_config_core_v3.TransportSocket, error) {
	if endpoint.Scheme != "https" {
		return nil, nil
	}

	validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		MatchTypedSubjectAltNames: []*envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			b.buildSubjectAltNameMatcher(endpoint, options.OverrideCertificateName),
		},
	}
	bs, err := getCombinedCertificateAuthority(options.CA, options.CAFile)
	if err != nil {
		log.Error(ctx).Err(err).Msg("unable to enable certificate verification because no root CAs were found")
	} else {
		validationContext.TrustedCa = b.filemgr.BytesDataSource("ca.pem", bs)
	}
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			AlpnProtocols: []string{"h2", "http/1.1"},
			ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: validationContext,
			},
		},
		Sni: b.buildSubjectNameIndication(endpoint, options.OverrideCertificateName),
	}
	tlsConfig := marshalAny(tlsContext)
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: tlsConfig,
		},
	}, nil
}

func (b *Builder) buildPolicyTransportSocket(
	ctx context.Context,
	options *config.Options,
	policy *config.Policy,
	dst url.URL,
) (*envoy_config_core_v3.TransportSocket, error) {
	if dst.Scheme != "https" {
		return nil, nil
	}

	upstreamProtocol := getUpstreamProtocolForPolicy(ctx, policy)

	vc, err := b.buildPolicyValidationContext(ctx, options, policy, dst)
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
				CipherSuites: []string{
					"ECDHE-ECDSA-AES256-GCM-SHA384",
					"ECDHE-RSA-AES256-GCM-SHA384",
					"ECDHE-ECDSA-AES128-GCM-SHA256",
					"ECDHE-RSA-AES128-GCM-SHA256",
					"ECDHE-ECDSA-CHACHA20-POLY1305",
					"ECDHE-RSA-CHACHA20-POLY1305",
					"ECDHE-ECDSA-AES128-SHA",
					"ECDHE-RSA-AES128-SHA",
					"AES128-GCM-SHA256",
					"AES128-SHA",
					"ECDHE-ECDSA-AES256-SHA",
					"ECDHE-RSA-AES256-SHA",
					"AES256-GCM-SHA384",
					"AES256-SHA",
				},
				EcdhCurves: []string{
					"X25519",
					"P-256",
					"P-384",
					"P-521",
				},
			},
			AlpnProtocols: buildUpstreamALPN(upstreamProtocol),
			ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: vc,
			},
		},
		Sni: sni,
	}
	if policy.ClientCertificate != nil {
		tlsContext.CommonTlsContext.TlsCertificates = append(tlsContext.CommonTlsContext.TlsCertificates,
			b.envoyTLSCertificateFromGoTLSCertificate(ctx, policy.ClientCertificate))
	}

	tlsConfig := marshalAny(tlsContext)
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: tlsConfig,
		},
	}, nil
}

func (b *Builder) buildPolicyValidationContext(
	ctx context.Context,
	options *config.Options,
	policy *config.Policy,
	dst url.URL,
) (*envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext, error) {
	validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		MatchTypedSubjectAltNames: []*envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			b.buildSubjectAltNameMatcher(&dst, policy.TLSServerName),
		},
	}
	if policy.TLSCustomCAFile != "" {
		validationContext.TrustedCa = b.filemgr.FileDataSource(policy.TLSCustomCAFile)
	} else if policy.TLSCustomCA != "" {
		bs, err := base64.StdEncoding.DecodeString(policy.TLSCustomCA)
		if err != nil {
			log.Error(ctx).Err(err).Msg("invalid custom CA certificate")
		}
		validationContext.TrustedCa = b.filemgr.BytesDataSource("custom-ca.pem", bs)
	} else {
		bs, err := getCombinedCertificateAuthority(options.CA, options.CAFile)
		if err != nil {
			log.Error(ctx).Err(err).Msg("unable to enable certificate verification because no root CAs were found")
		} else {
			validationContext.TrustedCa = b.filemgr.BytesDataSource("ca.pem", bs)
		}
	}

	if policy.TLSSkipVerify {
		validationContext.TrustChainVerification = envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED
	}

	return validationContext, nil
}

func (b *Builder) buildCluster(
	cluster *envoy_config_cluster_v3.Cluster,
	name string,
	endpoints []Endpoint,
	upstreamProtocol upstreamProtocolConfig,
) error {
	if len(endpoints) == 0 {
		return errNoEndpoints
	}

	if cluster.ConnectTimeout == nil {
		cluster.ConnectTimeout = defaultConnectionTimeout
	}
	cluster.RespectDnsTtl = true
	lbEndpoints, err := b.buildLbEndpoints(endpoints)
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
	cluster.TransportSocketMatches, err = b.buildTransportSocketMatches(endpoints)
	if err != nil {
		return err
	}
	// Set the default transport socket to the first socket match. This is necessary so that ALPN
	// auto configuration works.
	if len(cluster.TransportSocketMatches) > 0 {
		cluster.TransportSocket = cluster.TransportSocketMatches[0].TransportSocket
	}

	cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": marshalAny(buildUpstreamProtocolOptions(endpoints, upstreamProtocol)),
	}

	cluster.ClusterDiscoveryType = getClusterDiscoveryType(lbEndpoints)

	return cluster.Validate()
}

// grpcAuthorizeOutlierDetection defines slightly more aggressive malfunction detection for authorize endpoints
func grpcAuthorizeOutlierDetection() *envoy_config_cluster_v3.OutlierDetection {
	return &envoy_config_cluster_v3.OutlierDetection{
		Consecutive_5Xx:                       wrapperspb.UInt32(5),
		Interval:                              durationpb.New(time.Second * 10),
		BaseEjectionTime:                      durationpb.New(time.Second * 30),
		MaxEjectionPercent:                    wrapperspb.UInt32(100),
		EnforcingConsecutive_5Xx:              wrapperspb.UInt32(100),
		EnforcingSuccessRate:                  wrapperspb.UInt32(100),
		SuccessRateMinimumHosts:               wrapperspb.UInt32(2),
		SuccessRateRequestVolume:              wrapperspb.UInt32(10),
		SuccessRateStdevFactor:                wrapperspb.UInt32(1900),
		ConsecutiveGatewayFailure:             wrapperspb.UInt32(5),
		EnforcingConsecutiveGatewayFailure:    wrapperspb.UInt32(0),
		SplitExternalLocalOriginErrors:        false,
		FailurePercentageThreshold:            wrapperspb.UInt32(85),
		EnforcingFailurePercentage:            wrapperspb.UInt32(100),
		EnforcingFailurePercentageLocalOrigin: wrapperspb.UInt32(100),
		FailurePercentageMinimumHosts:         wrapperspb.UInt32(2),
		FailurePercentageRequestVolume:        wrapperspb.UInt32(10),
		MaxEjectionTime:                       durationpb.New(time.Minute * 5),
	}
}

func grpcHealthChecks(name string) []*envoy_config_core_v3.HealthCheck {
	return []*envoy_config_core_v3.HealthCheck{{
		Timeout:               durationpb.New(time.Second * 10),
		Interval:              durationpb.New(time.Second * 10),
		InitialJitter:         durationpb.New(time.Millisecond * 100),
		IntervalJitter:        durationpb.New(time.Millisecond * 100),
		IntervalJitterPercent: 10,
		UnhealthyThreshold:    wrapperspb.UInt32(1),
		HealthyThreshold:      wrapperspb.UInt32(1),
		ReuseConnection:       wrapperspb.Bool(true),
		NoTrafficInterval:     durationpb.New(time.Minute),
		HealthChecker: &envoy_config_core_v3.HealthCheck_GrpcHealthCheck_{
			GrpcHealthCheck: &envoy_config_core_v3.HealthCheck_GrpcHealthCheck{
				ServiceName: name,
			},
		},
	}}
}

func (b *Builder) buildLbEndpoints(endpoints []Endpoint) ([]*envoy_config_endpoint_v3.LbEndpoint, error) {
	var lbes []*envoy_config_endpoint_v3.LbEndpoint
	for _, e := range endpoints {
		defaultPort := 80
		if e.transportSocket != nil && e.transportSocket.Name == "tls" {
			defaultPort = 443
		}

		u := e.url
		if e.url.Hostname() == "localhost" {
			u.Host = strings.Replace(e.url.Host, "localhost", "127.0.0.1", -1)
		}

		lbe := &envoy_config_endpoint_v3.LbEndpoint{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: buildAddress(u.Host, defaultPort),
				},
			},
			LoadBalancingWeight: e.loadBalancerWeight,
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

func (b *Builder) buildTransportSocketMatches(endpoints []Endpoint) ([]*envoy_config_cluster_v3.Cluster_TransportSocketMatch, error) {
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

// validateClusters contains certain rules that must match
func validateClusters(clusters []*envoy_config_cluster_v3.Cluster) error {
	return validateClusterNamesUnique(clusters)
}

// validateClusterNamesUnique checks cluster names are unique, as they're effectively IDs
func validateClusterNamesUnique(clusters []*envoy_config_cluster_v3.Cluster) error {
	names := make(map[string]bool, len(clusters))

	for _, c := range clusters {
		if _, there := names[c.Name]; there {
			return fmt.Errorf("route %s is not unique", c.Name)
		}
		names[c.Name] = true
	}

	return nil
}

func getClusterDiscoveryType(lbEndpoints []*envoy_config_endpoint_v3.LbEndpoint) *envoy_config_cluster_v3.Cluster_Type {
	// for IPs we use a static discovery type, otherwise we use DNS
	allIP := true
	for _, lbe := range lbEndpoints {
		if net.ParseIP(urlutil.StripPort(lbe.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())) == nil {
			allIP = false
		}
	}
	if allIP {
		return &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	}
	return &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STRICT_DNS}
}
