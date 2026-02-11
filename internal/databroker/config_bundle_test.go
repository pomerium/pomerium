package databroker_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func TestConfigBundle(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		bundle := databroker.NewConfigBundle()
		assert.Empty(t, cmp.Diff(&configpb.Config{
			Name:     "test",
			Settings: &configpb.Settings{},
		}, bundle.Snapshot("test"), protocmp.Transform()))
	})
	t.Run("references", func(t *testing.T) {
		t.Parallel()

		bundle := databroker.NewConfigBundle()
		for i := range 15 {
			bundle.KeyPairs[fmt.Sprintf("kp%d", i)] = &configpb.KeyPair{
				Id:          proto.String(fmt.Sprintf("kp%d", i)),
				Certificate: []byte(fmt.Sprintf("kp%d-certificate", i)),
				Key:         []byte(fmt.Sprintf("kp%d-key", i)),
			}
		}
		for i := range 10 {
			bundle.Policies[fmt.Sprintf("p%d", i)] = &configpb.Policy{
				AssignedRoutes: []*configpb.EntityInfo{{Id: proto.String("assigned")}},
				CreatedAt:      timestamppb.Now(),
				EnforcedRoutes: []*configpb.EntityInfo{{Id: proto.String("enforced")}},
				Id:             proto.String(fmt.Sprintf("p%d", i)),
				ModifiedAt:     timestamppb.Now(),
				NamespaceName:  proto.String("namespace"),
			}
		}
		bundle.Routes["r1"] = &configpb.Route{
			AssignedPolicies:                       []*configpb.EntityInfo{{Id: proto.String("assigned")}},
			CreatedAt:                              timestamppb.Now(),
			EnforcedPolicies:                       []*configpb.EntityInfo{{Id: proto.String("enforced")}},
			Id:                                     proto.String("r1"),
			KubernetesServiceAccountTokenKeyPairId: proto.String("kp1"),
			ModifiedAt:                             timestamppb.Now(),
			NamespaceName:                          proto.String("namespace"),
			PolicyIds:                              []string{"p1", "p2", "p3"},
			TlsClientKeyPairId:                     proto.String("kp2"),
			TlsCustomCaKeyPairId:                   proto.String("kp3"),
			TlsDownstreamClientCaKeyPairId:         proto.String("kp4"),
		}
		bundle.Settings["s1"] = &configpb.Settings{
			AutocertCaKeyPairId:           proto.String("kp5"),
			AutocertTrustedCaKeyPairId:    proto.String("kp6"),
			CertificateAuthorityKeyPairId: proto.String("kp7"),
			CertificateKeyPairIds:         []string{"kp8", "kp9"},
			CookieName:                    proto.String("s1-cookie"),
			CreatedAt:                     timestamppb.Now(),
			MetricsClientCaKeyPairId:      proto.String("kp10"),
			ModifiedAt:                    timestamppb.Now(),
			SshHostKeyPairIds:             []string{"kp11", "kp12", "kp13"},
			SshUserCaKeyPairId:            proto.String("kp14"),
		}
		bundle.Settings["s2"] = &configpb.Settings{
			CookieName: proto.String("s2-cookie"),
		}
		assert.Empty(t, cmp.Diff(&configpb.Config{
			Name: "test",
			Routes: []*configpb.Route{
				{
					Id:                            proto.String("r1"),
					KubernetesServiceAccountToken: "kp1-key",
					Policies: []*configpb.Policy{
						{Id: proto.String("p1")},
						{Id: proto.String("p2")},
						{Id: proto.String("p3")},
					},
					TlsClientCert:         "kp2-certificate",
					TlsClientKey:          "kp2-key",
					TlsCustomCa:           "kp3-certificate",
					TlsDownstreamClientCa: "kp4-certificate",
				},
			},
			Settings: &configpb.Settings{
				AutocertCa:           proto.String("kp5-certificate"),
				AutocertTrustedCa:    proto.String("kp6-certificate"),
				CertificateAuthority: proto.String("kp7-certificate"),
				Certificates: []*configpb.Settings_Certificate{
					{CertBytes: []byte("kp8-certificate"), KeyBytes: []byte("kp8-key")},
					{CertBytes: []byte("kp9-certificate"), KeyBytes: []byte("kp9-key")},
				},
				CookieName:      proto.String("s2-cookie"),
				MetricsClientCa: proto.String("kp10-certificate"),
				SshHostKeys: &configpb.Settings_StringList{Values: []string{
					"kp11-certificate",
					"kp12-certificate",
					"kp13-certificate",
				}},
				SshUserCaKey: proto.String("kp14-certificate"),
			},
		}, bundle.Snapshot("test"), protocmp.Transform()))
	})
}
