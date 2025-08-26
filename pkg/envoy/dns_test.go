package envoy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_extensions_network_dns_resolver_cares_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/network/dns_resolver/cares/v3"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestDNSCrash(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(t.Context())
	errSentAll := errors.New("sent all")
	cnt := int64(10000)

	dnsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = dnsListener.Close() })

	var timesCalled int64
	dnsServer := &dns.Server{
		Listener: dnsListener,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := &dns.Msg{}
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)

			if atomic.AddInt64(&timesCalled, 1) == cnt {
				go func() {
					cancel(errSentAll)
				}()
			}
		}),
	}
	go dnsServer.ActivateAndServe()
	t.Cleanup(func() { dnsServer.Shutdown() })

	_, dnsPortStr, err := net.SplitHostPort(dnsListener.Addr().String())
	require.NoError(t, err)
	dnsPort, err := strconv.ParseUint(dnsPortStr, 10, 64)
	require.NoError(t, err)

	dir := t.TempDir()
	envoyPath := filepath.Join(dir, "envoy")
	require.NoError(t, extract(envoyPath))

	var endpoints []*envoy_config_endpoint_v3.LocalityLbEndpoints
	for i := range cnt {
		endpoints = append(endpoints, &envoy_config_endpoint_v3.LocalityLbEndpoints{
			LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
				HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
					Endpoint: &envoy_config_endpoint_v3.Endpoint{
						Address: &envoy_config_core_v3.Address{
							Address: &envoy_config_core_v3.Address_SocketAddress{
								SocketAddress: &envoy_config_core_v3.SocketAddress{
									Address: fmt.Sprintf("www%d.example.com", i),
									PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
										PortValue: 80,
									},
								},
							},
						},
					},
				},
			}},
		})
	}
	config := protojson.Format(&envoy_config_bootstrap_v3.Bootstrap{
		StaticResources: &envoy_config_bootstrap_v3.Bootstrap_StaticResources{
			Clusters: []*envoy_config_cluster_v3.Cluster{{
				Name: "example",
				ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
					Type: envoy_config_cluster_v3.Cluster_STRICT_DNS,
				},
				LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
					ClusterName: "example",
					Endpoints:   endpoints,
				},
			}},
		},
		TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
			Name: "envoy.network.dns_resolver.cares",
			TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
				Resolvers: []*envoy_config_core_v3.Address{{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Address: "127.0.0.1",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: uint32(dnsPort),
							},
						},
					},
				}},
				DnsResolverOptions: &envoy_config_core_v3.DnsResolverOptions{
					UseTcpForDnsLookups: true,
				},
				QueryTimeoutSeconds: wrapperspb.UInt64(1),
			}),
		},
	})
	configPath := filepath.Join(dir, "envoy.json")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o0600))

	c := exec.CommandContext(ctx, envoyPath,
		"--log-level", "debug",
		"--config-path", configPath,
	)
	stdout, err := c.StdoutPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdout.Close() })
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			t.Log(s.Text())
		}
	}()
	stderr, err := c.StderrPipe()
	require.NoError(t, err)
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			t.Log(s.Text())
		}
	}()
	t.Cleanup(func() { _ = stderr.Close() })

	err = c.Run()
	if errors.Is(context.Cause(ctx), errSentAll) {
		err = nil
	}
	assert.NoError(t, err)
}
