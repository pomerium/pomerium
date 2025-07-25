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
	envoy_extensions_clusters_common_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	envoy_extensions_clusters_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dns/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// BuildClusters builds envoy clusters from the given config.
func (b *Builder) BuildClusters(ctx context.Context, cfg *config.Config) ([]*envoy_config_cluster_v3.Cluster, error) {
	ctx, span := trace.Continue(ctx, "envoyconfig.Builder.BuildClusters")
	defer span.End()

	grpcURLs := []*url.URL{{
		Scheme: "http",
		Host:   b.localGRPCAddress,
	}}
	httpURL := &url.URL{
		Scheme: "http",
		Host:   b.localHTTPAddress,
	}
	metricsURL := &url.URL{
		Scheme: "http",
		Host:   b.localMetricsAddress,
	}

	authorizeURLs := grpcURLs
	if !config.IsAuthorize(cfg.Options.Services) {
		var err error
		authorizeURLs, err = cfg.Options.GetInternalAuthorizeURLs()
		if err != nil {
			return nil, err
		}
	}

	databrokerURLs := grpcURLs
	if !config.IsDataBroker(cfg.Options.Services) {
		var err error
		databrokerURLs, err = cfg.Options.GetDataBrokerURLs()
		if err != nil {
			return nil, err
		}
	}

	controlGRPC, err := b.buildInternalCluster(ctx, cfg, "pomerium-control-plane-grpc", grpcURLs, upstreamProtocolHTTP2, Keepalive(false))
	if err != nil {
		return nil, err
	}

	controlHTTP, err := b.buildInternalCluster(ctx, cfg, "pomerium-control-plane-http", []*url.URL{httpURL}, upstreamProtocolAuto, Keepalive(false))
	if err != nil {
		return nil, err
	}

	controlMetrics, err := b.buildInternalCluster(ctx, cfg, "pomerium-control-plane-metrics", []*url.URL{metricsURL}, upstreamProtocolAuto, Keepalive(false))
	if err != nil {
		return nil, err
	}

	authorizeCluster, err := b.buildInternalCluster(ctx, cfg, "pomerium-authorize", authorizeURLs, upstreamProtocolHTTP2, Keepalive(false))
	if err != nil {
		return nil, err
	}
	if len(authorizeURLs) > 1 {
		authorizeCluster.HealthChecks = grpcHealthChecks("pomerium-authorize")
		authorizeCluster.OutlierDetection = grpcOutlierDetection()
	}

	databrokerKeepalive := Keepalive(cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagGRPCDatabrokerKeepalive))
	databrokerCluster, err := b.buildInternalCluster(ctx, cfg, "pomerium-databroker", databrokerURLs, upstreamProtocolHTTP2, databrokerKeepalive)
	if err != nil {
		return nil, err
	}
	if len(databrokerURLs) > 1 {
		databrokerCluster.HealthChecks = grpcHealthChecks("pomerium-databroker")
		databrokerCluster.OutlierDetection = grpcOutlierDetection()
	}

	envoyAdminCluster, err := b.buildEnvoyAdminCluster(ctx, cfg)
	if err != nil {
		return nil, err
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		b.buildACMETLSALPNCluster(cfg),
		controlGRPC,
		controlHTTP,
		controlMetrics,
		authorizeCluster,
		databrokerCluster,
		envoyAdminCluster,
	}

	if config.IsProxy(cfg.Options.Services) {
		for policy := range cfg.Options.GetAllPolicies() {
			if len(policy.To) > 0 {
				cluster, err := b.buildPolicyCluster(ctx, cfg, policy)
				if err != nil {
					return nil, fmt.Errorf("policy %q: %w", policy.String(), err)
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

var defaultTCPKeepalive = &envoy_config_core_v3.TcpKeepalive{
	KeepaliveTime:     wrapperspb.UInt32(15),
	KeepaliveInterval: wrapperspb.UInt32(15),
}

func (b *Builder) buildInternalCluster(
	ctx context.Context,
	cfg *config.Config,
	name string,
	dsts []*url.URL,
	upstreamProtocol upstreamProtocolConfig,
	keepalive Keepalive,
) (*envoy_config_cluster_v3.Cluster, error) {
	cluster := newDefaultEnvoyClusterConfig()
	// Match the Go standard library default TCP keepalive settings.
	cluster.UpstreamConnectionOptions = &envoy_config_cluster_v3.UpstreamConnectionOptions{
		TcpKeepalive: defaultTCPKeepalive,
	}
	var endpoints []Endpoint
	for _, dst := range dsts {
		ts, err := b.buildInternalTransportSocket(ctx, cfg, dst)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, NewEndpoint(dst, ts, 1))
	}
	dnsLookupFamily := config.GetEnvoyDNSLookupFamily(cfg.Options.DNSLookupFamily)
	if err := b.buildCluster(
		cluster, name, endpoints, upstreamProtocol, dnsLookupFamily, keepalive,
	); err != nil {
		return nil, err
	}
	cluster.CircuitBreakers = buildInternalCircuitBreakers(cfg)

	return cluster, nil
}

func (b *Builder) buildPolicyCluster(ctx context.Context, cfg *config.Config, policy *config.Policy) (*envoy_config_cluster_v3.Cluster, error) {
	var cluster *envoy_config_cluster_v3.Cluster
	if policy.EnvoyOpts != nil {
		cluster = proto.Clone(policy.EnvoyOpts).(*envoy_config_cluster_v3.Cluster)
	} else {
		cluster = newDefaultEnvoyClusterConfig()
	}

	options := cfg.Options

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
		}
	}

	cluster.AltStatName = getClusterStatsName(policy)
	upstreamProtocol := getUpstreamProtocolForPolicy(ctx, policy)

	name := getClusterID(policy)
	endpoints, err := b.buildPolicyEndpoints(ctx, cfg, policy)
	if err != nil {
		return nil, err
	}

	dnsLookupFamily := config.GetEnvoyDNSLookupFamily(options.DNSLookupFamily)
	if policy.EnableGoogleCloudServerlessAuthentication {
		dnsLookupFamily = envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_ONLY
	}

	if err := b.buildCluster(
		cluster, name, endpoints, upstreamProtocol, dnsLookupFamily, Keepalive(false),
	); err != nil {
		return nil, err
	}
	cluster.CircuitBreakers = buildRouteCircuitBreakers(cfg, policy)

	return cluster, nil
}

func (b *Builder) buildPolicyEndpoints(
	ctx context.Context,
	cfg *config.Config,
	policy *config.Policy,
) ([]Endpoint, error) {
	var endpoints []Endpoint
	for _, dst := range policy.To {
		ts, err := b.buildPolicyTransportSocket(ctx, cfg, policy, dst.URL)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, NewEndpoint(&dst.URL, ts, dst.LbWeight))
	}
	return endpoints, nil
}

func (b *Builder) buildInternalTransportSocket(
	ctx context.Context,
	cfg *config.Config,
	endpoint *url.URL,
) (*envoy_config_core_v3.TransportSocket, error) {
	if endpoint.Scheme != "https" {
		return nil, nil
	}

	validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		MatchTypedSubjectAltNames: []*envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			b.buildSubjectAltNameMatcher(endpoint, cfg.Options.OverrideCertificateName),
		},
	}
	bs, err := getCombinedCertificateAuthority(ctx, cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
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
		Sni: b.buildSubjectNameIndication(endpoint, cfg.Options.OverrideCertificateName),
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
	cfg *config.Config,
	policy *config.Policy,
	dst url.URL,
) (*envoy_config_core_v3.TransportSocket, error) {
	if dst.Scheme != "https" {
		return nil, nil
	}

	upstreamProtocol := getUpstreamProtocolForPolicy(ctx, policy)

	vc, err := b.buildPolicyValidationContext(ctx, cfg, policy, dst)
	if err != nil {
		return nil, err
	}

	sni := dst.Hostname()
	if policy.TLSServerName != "" {
		sni = policy.TLSServerName
	}
	if policy.TLSUpstreamServerName != "" {
		sni = policy.TLSUpstreamServerName
	}
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams:     tlsUpstreamParams,
			AlpnProtocols: buildUpstreamALPN(upstreamProtocol),
			ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: vc,
			},
		},
		Sni:                sni,
		AllowRenegotiation: policy.TLSUpstreamAllowRenegotiation,
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
	cfg *config.Config,
	policy *config.Policy,
	dst url.URL,
) (*envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext, error) {
	overrideName := ""
	if policy.TLSServerName != "" {
		overrideName = policy.TLSServerName
	}
	if policy.TLSUpstreamServerName != "" {
		overrideName = policy.TLSUpstreamServerName
	}
	validationContext := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		MatchTypedSubjectAltNames: []*envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			b.buildSubjectAltNameMatcher(&dst, overrideName),
		},
	}
	if policy.TLSCustomCAFile != "" {
		validationContext.TrustedCa = b.filemgr.FileDataSource(policy.TLSCustomCAFile)
	} else if policy.TLSCustomCA != "" {
		bs, err := base64.StdEncoding.DecodeString(policy.TLSCustomCA)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("invalid custom CA certificate")
		}
		validationContext.TrustedCa = b.filemgr.BytesDataSource("custom-ca.pem", bs)
	} else {
		bs, err := getCombinedCertificateAuthority(ctx, cfg)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("unable to enable certificate verification because no root CAs were found")
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
	dnsLookupFamily envoy_extensions_clusters_common_dns_v3.DnsLookupFamily,
	keepalive Keepalive,
) error {
	if len(endpoints) == 0 {
		return errNoEndpoints
	}

	if cluster.ConnectTimeout == nil {
		cluster.ConnectTimeout = defaultConnectionTimeout
	}
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

	cluster.TypedExtensionProtocolOptions = buildTypedExtensionProtocolOptions(endpoints, upstreamProtocol, keepalive)

	cluster.ClusterDiscoveryType = getClusterDiscoveryType(lbEndpoints, dnsLookupFamily)

	return cluster.Validate()
}

// grpcOutlierDetection defines slightly more aggressive malfunction detection for grpc endpoints
func grpcOutlierDetection() *envoy_config_cluster_v3.OutlierDetection {
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
		defaultPort := uint32(80)
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
					Address:  buildTCPAddress(u.Host, defaultPort),
					Hostname: e.url.Host,
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

func allIPAddresses(lbEndpoints []*envoy_config_endpoint_v3.LbEndpoint) bool {
	for _, lbe := range lbEndpoints {
		if net.ParseIP(urlutil.StripPort(lbe.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())) == nil {
			return false
		}
	}
	return true
}

func getClusterDiscoveryType(
	lbEndpoints []*envoy_config_endpoint_v3.LbEndpoint,
	dnsLookupFamily envoy_extensions_clusters_common_dns_v3.DnsLookupFamily,
) *envoy_config_cluster_v3.Cluster_ClusterType {
	// for IPs we use a static discovery type, otherwise we use DNS
	if allIPAddresses(lbEndpoints) {
		return &envoy_config_cluster_v3.Cluster_ClusterType{
			ClusterType: &envoy_config_cluster_v3.Cluster_CustomClusterType{
				Name: "envoy.cluster.static",
			},
		}
	}

	return &envoy_config_cluster_v3.Cluster_ClusterType{
		ClusterType: &envoy_config_cluster_v3.Cluster_CustomClusterType{
			Name: "envoy.clusters.dns",
			TypedConfig: marshalAny(&envoy_extensions_clusters_dns_v3.DnsCluster{
				RespectDnsTtl:   true,
				DnsLookupFamily: dnsLookupFamily,
			}),
		},
	}
}
