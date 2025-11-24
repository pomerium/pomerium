package ssh_test

import (
	"context"
	"errors"
	"testing"
	"time"

	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh"
	mock_ssh "github.com/pomerium/pomerium/pkg/ssh/mock"
)

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

const (
	eventuallyTimeout      = 2 * time.Second
	eventuallyPollInterval = 50 * time.Millisecond
)

func TestStreamManager(t *testing.T) {
	ctrl := gomock.NewController(t)
	auth := mock_ssh.NewMockAuthInterface(ctrl)

	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.Policies = []config.Policy{
		{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://dest1:22")},
		{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://dest2:22")},
	}
	m := ssh.NewStreamManager(t.Context(), auth, ssh.NewInMemoryPolicyIndexer(alwaysAllowEvaluator), cfg)
	// intentionally don't call m.Run() - simulate initial sync completing
	m.ClearRecords(t.Context())
	t.Run("LookupStream", func(t *testing.T) {
		assert.Nil(t, m.LookupStream(1234))
		sh := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
		done := make(chan error)
		ctx, ca := context.WithCancel(t.Context())
		go func() {
			done <- sh.Run(ctx)
		}()
		assert.Equal(t, sh, m.LookupStream(1234))
		sh.Close()
		assert.Nil(t, m.LookupStream(1234))
		ca()
		err := <-done
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("TerminateStreamOnSessionDelete", func(t *testing.T) {
		sh := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
		done := make(chan error)
		go func() {
			done <- sh.Run(t.Context())
		}()

		m.OnStreamAuthenticated(t.Context(), 1234, ssh.Request{SessionID: "test-id-1", SessionBindingID: "binding-1"})
		m.UpdateRecords(t.Context(), 0, []*databroker.Record{
			{
				Type: "type.googleapis.com/session.Session",
				Id:   "test-id-1",
				Data: marshalAny(&session.Session{}),
			},
			{
				Type:      "type.googleapis.com/session.Session",
				Id:        "test-id-1",
				Data:      marshalAny(&session.Session{}),
				DeletedAt: timestamppb.Now(),
			},
		})
		select {
		case err := <-done:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
	})

	t.Run("TerminateMultipleStreamsForSession", func(t *testing.T) {
		sh1 := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1})
		done1 := make(chan error)
		go func() {
			done1 <- sh1.Run(t.Context())
		}()
		sh2 := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 2})
		done2 := make(chan error)
		go func() {
			done2 <- sh2.Run(t.Context())
		}()
		m.OnStreamAuthenticated(t.Context(), 1, ssh.Request{SessionID: "test-id-1", SessionBindingID: "binding-1"})
		m.OnStreamAuthenticated(t.Context(), 2, ssh.Request{SessionID: "test-id-1", SessionBindingID: "binding-1"})
		m.UpdateRecords(t.Context(), 0, []*databroker.Record{
			{
				Type: "type.googleapis.com/session.Session",
				Id:   "test-id-1",
				Data: marshalAny(&session.Session{}),
			},
			{
				Type:      "type.googleapis.com/session.Session",
				Id:        "test-id-1",
				Data:      marshalAny(&session.Session{}),
				DeletedAt: timestamppb.Now(),
			},
		})
		select {
		case err := <-done1:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
		select {
		case err := <-done2:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
	})

	t.Run("ClearRecords", func(t *testing.T) {
		sh1 := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1})
		done1 := make(chan error)
		go func() {
			done1 <- sh1.Run(t.Context())
		}()
		sh2 := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 2})
		done2 := make(chan error)
		go func() {
			done2 <- sh2.Run(t.Context())
		}()
		m.OnStreamAuthenticated(t.Context(), 1, ssh.Request{SessionID: "test-id-1", SessionBindingID: "binding-1"})
		m.OnStreamAuthenticated(t.Context(), 2, ssh.Request{SessionID: "test-id-2", SessionBindingID: "binding-2"})
		m.ClearRecords(t.Context())
		select {
		case err := <-done1:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
		select {
		case err := <-done2:
			assert.ErrorIs(t, err, status.Errorf(codes.PermissionDenied, "no longer authorized"))
		case <-time.After(1 * time.Second):
			t.Fail()
		}
	})
}

func TestReverseTunnelEDS(t *testing.T) {
	ctrl := gomock.NewController(t)
	auth := mock_ssh.NewMockAuthInterface(ctrl)

	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.SSHAddr = "localhost:2200"
	cfg.Options.Policies = []config.Policy{
		{From: "ssh://host1", To: mustParseWeightedURLs(t, "ssh://dest1:22"), UpstreamTunnel: &config.UpstreamTunnel{}, AllowPublicUnauthenticatedAccess: true},
		{From: "ssh://host2", To: mustParseWeightedURLs(t, "ssh://dest2:22"), UpstreamTunnel: &config.UpstreamTunnel{}, AllowPublicUnauthenticatedAccess: true},
	}

	route1ClusterID := envoyconfig.GetClusterID(&cfg.Options.Policies[0])
	route2ClusterID := envoyconfig.GetClusterID(&cfg.Options.Policies[1])

	expectedMd1 := &extensions_ssh.EndpointMetadata{
		ServerPort: &extensions_ssh.ServerPort{
			Value:     22,
			IsDynamic: false,
		},
		MatchedPermission: &extensions_ssh.PortForwardPermission{
			RequestedHost: "host1",
			RequestedPort: 22,
		},
	}
	expectedMd2 := &extensions_ssh.EndpointMetadata{
		ServerPort: &extensions_ssh.ServerPort{
			Value:     22,
			IsDynamic: false,
		},
		MatchedPermission: &extensions_ssh.PortForwardPermission{
			RequestedHost: "host2",
			RequestedPort: 22,
		},
	}

	key := newSSHKey(t)
	sshKey, _ := gossh.NewPublicKey(key.Public())
	authRequest := &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_AuthRequest{
			AuthRequest: &extensions_ssh.AuthenticationRequest{
				Protocol:   "ssh",
				Service:    "ssh-connection",
				Username:   "user",
				AuthMethod: "publickey",
				MethodRequest: marshalAny(&extensions_ssh.PublicKeyMethodRequest{
					PublicKey:                  key,
					PublicKeyAlg:               "ssh-ed25519",
					PublicKeyFingerprintSha256: []byte(gossh.FingerprintSHA256(sshKey)),
				}),
			},
		},
	}
	auth.EXPECT().
		HandlePublicKeyMethodRequest(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, ssh.StreamAuthInfo, *extensions_ssh.PublicKeyMethodRequest) (ssh.PublicKeyAuthMethodResponse, error) {
			return ssh.PublicKeyAuthMethodResponse{
				Allow: &extensions_ssh.PublicKeyAllowResponse{
					PublicKey: []byte(gossh.FingerprintSHA256(sshKey)),
				},
			}, nil
		}).
		AnyTimes()
	auth.EXPECT().
		EvaluateDelayed(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, ssh.StreamAuthInfo) error {
			return nil
		}).
		AnyTimes()
	forwardRequest1 := &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_GlobalRequest{
			GlobalRequest: &extensions_ssh.GlobalRequest{
				WantReply: false,
				Request: &extensions_ssh.GlobalRequest_TcpipForwardRequest{
					TcpipForwardRequest: &extensions_ssh.TcpipForwardRequest{
						RemoteAddress: "host1",
						RemotePort:    22,
					},
				},
			},
		},
	}

	forwardRequest2 := &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_GlobalRequest{
			GlobalRequest: &extensions_ssh.GlobalRequest{
				WantReply: false,
				Request: &extensions_ssh.GlobalRequest_TcpipForwardRequest{
					TcpipForwardRequest: &extensions_ssh.TcpipForwardRequest{
						RemoteAddress: "host2",
						RemotePort:    22,
					},
				},
			},
		},
	}

	cancelRequest1 := &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_GlobalRequest{
			GlobalRequest: &extensions_ssh.GlobalRequest{
				WantReply: false,
				Request: &extensions_ssh.GlobalRequest_CancelTcpipForwardRequest{
					CancelTcpipForwardRequest: &extensions_ssh.CancelTcpipForwardRequest{
						RemoteAddress: "host1",
						RemotePort:    22,
					},
				},
			},
		},
	}

	cancelRequest2 := &extensions_ssh.ClientMessage{
		Message: &extensions_ssh.ClientMessage_GlobalRequest{
			GlobalRequest: &extensions_ssh.GlobalRequest{
				WantReply: false,
				Request: &extensions_ssh.GlobalRequest_CancelTcpipForwardRequest{
					CancelTcpipForwardRequest: &extensions_ssh.CancelTcpipForwardRequest{
						RemoteAddress: "host2",
						RemotePort:    22,
					},
				},
			},
		},
	}

	t.Run("Single Endpoint", func(t *testing.T) {
		for range 10 {
			m := ssh.NewStreamManager(t.Context(), auth, ssh.NewInMemoryPolicyIndexer(alwaysAllowEvaluator), cfg)
			client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
			client.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ *databroker.SyncLatestRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[databroker.SyncLatestResponse], error) {
					<-ctx.Done()
					return nil, context.Cause(ctx)
				}).AnyTimes()
			auth.EXPECT().GetDataBrokerServiceClient().Return(client).AnyTimes()

			go m.Run(t.Context())
			m.ClearRecords(t.Context())

			ctx, ca := context.WithCancelCause(t.Context())
			t.Cleanup(func() {
				ca(errors.New("test cleanup"))
			})
			errTestDone := errors.New("test done")
			sh := m.NewStreamHandler(ctx, &extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
			done := make(chan error)
			go func() {
				err := sh.Run(ctx)
				assert.ErrorIs(t, err, errTestDone)
				close(done)
			}()

			auth.EXPECT().
				EvaluatePortForward(gomock.Any(), gomock.Any(), gomock.All()).
				Return(nil).
				Times(2)
			sh.ReadC() <- authRequest

			sh.ReadC() <- forwardRequest1

			require.Eventually(t, func() bool {
				res := m.UnexportedEdsCache().GetResources()
				return len(res) == 1 &&
					len(res[route1ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment).Endpoints[0].LbEndpoints) == 1
			}, eventuallyTimeout, eventuallyPollInterval)

			{
				load1 := m.UnexportedEdsCache().GetResources()[route1ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment)
				assert.Equal(t, route1ClusterID, load1.ClusterName)
				assert.Len(t, load1.Endpoints, 1)
				assert.Len(t, load1.Endpoints[0].LbEndpoints, 1)
				assert.Equal(t, "ssh:1234", load1.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetAddress())

				actualMd, err := load1.Endpoints[0].LbEndpoints[0].GetMetadata().GetTypedFilterMetadata()["com.pomerium.ssh.endpoint"].UnmarshalNew()
				require.NoError(t, err)
				testutil.AssertProtoEqual(t, expectedMd1, actualMd)
			}

			sh.ReadC() <- forwardRequest2

			require.Eventually(t, func() bool {
				res := m.UnexportedEdsCache().GetResources()
				return len(res) == 2 &&
					len(res[route1ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment).Endpoints[0].LbEndpoints) == 1 &&
					len(res[route2ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment).Endpoints[0].LbEndpoints) == 1
			}, eventuallyTimeout, eventuallyPollInterval)

			{
				load1 := m.UnexportedEdsCache().GetResources()[route1ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment)
				assert.Equal(t, route1ClusterID, load1.ClusterName)
				assert.Len(t, load1.Endpoints, 1)
				assert.Len(t, load1.Endpoints[0].LbEndpoints, 1)
				assert.Equal(t, "ssh:1234", load1.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
				actualMd1, err := load1.Endpoints[0].LbEndpoints[0].GetMetadata().GetTypedFilterMetadata()["com.pomerium.ssh.endpoint"].UnmarshalNew()
				require.NoError(t, err)
				testutil.AssertProtoEqual(t, expectedMd1, actualMd1)

				load2 := m.UnexportedEdsCache().GetResources()[route2ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment)
				assert.Equal(t, route2ClusterID, load2.ClusterName)
				assert.Len(t, load2.Endpoints, 1)
				assert.Len(t, load2.Endpoints[0].LbEndpoints, 1)
				assert.Equal(t, "ssh:1234", load2.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
				actualMd2, err := load2.Endpoints[0].LbEndpoints[0].GetMetadata().GetTypedFilterMetadata()["com.pomerium.ssh.endpoint"].UnmarshalNew()
				require.NoError(t, err)
				testutil.AssertProtoEqual(t, expectedMd2, actualMd2)
			}

			sh.ReadC() <- cancelRequest1

			require.Eventually(t, func() bool {
				res := m.UnexportedEdsCache().GetResources()
				return len(res) == 1 &&
					len(res[route2ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment).Endpoints[0].LbEndpoints) == 1
			}, eventuallyTimeout, eventuallyPollInterval)

			{
				load2 := m.UnexportedEdsCache().GetResources()[route2ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment)
				assert.Equal(t, route2ClusterID, load2.ClusterName)
				assert.Len(t, load2.Endpoints, 1)
				assert.Len(t, load2.Endpoints[0].LbEndpoints, 1)
				assert.Equal(t, "ssh:1234", load2.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
				actualMd2, err := load2.Endpoints[0].LbEndpoints[0].GetMetadata().GetTypedFilterMetadata()["com.pomerium.ssh.endpoint"].UnmarshalNew()
				require.NoError(t, err)
				testutil.AssertProtoEqual(t, expectedMd2, actualMd2)
			}

			sh.ReadC() <- cancelRequest2

			require.Eventually(t, func() bool {
				res := m.UnexportedEdsCache().GetResources()
				return len(res) == 0
			}, eventuallyTimeout, eventuallyPollInterval)

			sh.Close()
			ca(errTestDone)
			<-done
		}
	})

	t.Run("Multi Endpoint", func(t *testing.T) {
		for range 10 {
			m := ssh.NewStreamManager(t.Context(), auth, ssh.NewInMemoryPolicyIndexer(alwaysAllowEvaluator), cfg)
			client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
			client.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ *databroker.SyncLatestRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[databroker.SyncLatestResponse], error) {
					<-ctx.Done()
					return nil, context.Cause(ctx)
				}).AnyTimes()
			auth.EXPECT().GetDataBrokerServiceClient().Return(client).AnyTimes()

			go m.Run(t.Context())
			m.ClearRecords(t.Context())

			ctx, ca := context.WithCancelCause(t.Context())
			t.Cleanup(func() {
				ca(errors.New("test cleanup"))
			})
			sh1 := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 1234})
			sh2 := m.NewStreamHandler(t.Context(), &extensions_ssh.DownstreamConnectEvent{StreamId: 2345})
			done1, done2 := make(chan struct{}), make(chan struct{})
			errTestDone := errors.New("test done")
			go func() {
				err := sh1.Run(ctx)
				assert.ErrorIs(t, err, errTestDone)
				close(done1)
			}()
			go func() {
				err := sh2.Run(ctx)
				assert.ErrorIs(t, err, errTestDone)
				close(done2)
			}()

			auth.EXPECT().
				EvaluatePortForward(gomock.Any(), gomock.Any(), gomock.All()).
				Return(nil).
				Times(4)
			sh1.ReadC() <- authRequest
			sh2.ReadC() <- authRequest

			sh1.ReadC() <- forwardRequest1
			sh2.ReadC() <- forwardRequest1

			check := func() {
				t.Helper()

				require.Eventually(t, func() bool {
					res := m.UnexportedEdsCache().GetResources()
					return len(res) == 1 && len(res[route1ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment).Endpoints[0].LbEndpoints) == 2
				}, eventuallyTimeout, eventuallyPollInterval)

				load1 := m.UnexportedEdsCache().GetResources()[route1ClusterID].(*envoy_config_endpoint_v3.ClusterLoadAssignment)
				assert.Equal(t, route1ClusterID, load1.ClusterName)
				require.Len(t, load1.Endpoints, 1)
				require.Len(t, load1.Endpoints[0].LbEndpoints, 2)
				//          locality ^^^^^^^^^    ^^^^^^^^^^^ endpoints

				assert.Equal(t, "ssh:1234", load1.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
				actualMd1, err := load1.Endpoints[0].LbEndpoints[0].GetMetadata().GetTypedFilterMetadata()["com.pomerium.ssh.endpoint"].UnmarshalNew()
				require.NoError(t, err)
				testutil.AssertProtoEqual(t, expectedMd1, actualMd1)

				assert.Equal(t, "ssh:2345", load1.Endpoints[0].LbEndpoints[1].GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
				actualMd1, err = load1.Endpoints[0].LbEndpoints[1].GetMetadata().GetTypedFilterMetadata()["com.pomerium.ssh.endpoint"].UnmarshalNew()
				require.NoError(t, err)
				testutil.AssertProtoEqual(t, expectedMd1, actualMd1)
			}
			check()

			cfg2 := cfg.Clone()
			cfg2.Options.Policies = nil
			m.OnConfigChange(cfg2)

			require.Eventually(t, func() bool {
				res := m.UnexportedEdsCache().GetResources()
				return len(res) == 0
			}, eventuallyTimeout, eventuallyPollInterval)

			auth.EXPECT().
				EvaluatePortForward(gomock.Any(), gomock.Any(), gomock.All()).
				Return(nil).
				Times(4)
			m.OnConfigChange(cfg)
			check()

			sh1.Close()
			sh2.Close()
			ca(errTestDone)
			<-done1
			<-done2

			require.Eventually(t, func() bool {
				res := m.UnexportedEdsCache().GetResources()
				return len(res) == 0
			}, eventuallyTimeout, eventuallyPollInterval)
		}
	})
}
