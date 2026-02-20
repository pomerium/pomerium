package databroker_test

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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
				Id:          new(fmt.Sprintf("kp%d", i)),
				Certificate: []byte(fmt.Sprintf("kp%d-certificate", i)),
				Key:         []byte(fmt.Sprintf("kp%d-key", i)),
			}
		}
		for i := range 10 {
			bundle.Policies[fmt.Sprintf("p%d", i)] = &configpb.Policy{
				AssignedRoutes: []*configpb.EntityInfo{{Id: new("assigned")}},
				CreatedAt:      timestamppb.Now(),
				EnforcedRoutes: []*configpb.EntityInfo{{Id: new("enforced")}},
				Id:             new(fmt.Sprintf("p%d", i)),
				ModifiedAt:     timestamppb.Now(),
				NamespaceName:  new("namespace"),
			}
		}
		bundle.Routes["r1"] = &configpb.Route{
			AssignedPolicies:                       []*configpb.EntityInfo{{Id: new("assigned")}},
			CreatedAt:                              timestamppb.Now(),
			EnforcedPolicies:                       []*configpb.EntityInfo{{Id: new("enforced")}},
			Id:                                     new("r1"),
			KubernetesServiceAccountTokenKeyPairId: new("kp1"),
			ModifiedAt:                             timestamppb.Now(),
			NamespaceName:                          new("namespace"),
			PolicyIds:                              []string{"p1", "p2", "p3"},
			TlsClientKeyPairId:                     new("kp2"),
			TlsCustomCaKeyPairId:                   new("kp3"),
			TlsDownstreamClientCaKeyPairId:         new("kp4"),
		}
		bundle.Settings["s1"] = &configpb.Settings{
			AutocertCaKeyPairId:           new("kp5"),
			AutocertTrustedCaKeyPairId:    new("kp6"),
			CertificateAuthorityKeyPairId: new("kp7"),
			CertificateKeyPairIds:         []string{"kp8", "kp9"},
			CookieName:                    new("s1-cookie"),
			CreatedAt:                     timestamppb.Now(),
			MetricsClientCaKeyPairId:      new("kp10"),
			ModifiedAt:                    timestamppb.Now(),
			SshHostKeyPairIds:             []string{"kp11", "kp12", "kp13"},
			SshUserCaKeyPairId:            new("kp14"),
		}
		bundle.Settings["s2"] = &configpb.Settings{
			CookieName: new("s2-cookie"),
		}
		assert.Empty(t, cmp.Diff(&configpb.Config{
			Name: "test",
			Routes: []*configpb.Route{
				{
					Id:                            new("r1"),
					KubernetesServiceAccountToken: "kp1-key",
					Policies: []*configpb.Policy{
						{Id: new("p1")},
						{Id: new("p2")},
						{Id: new("p3")},
					},
					TlsClientCert:         "kp2-certificate",
					TlsClientKey:          "kp2-key",
					TlsCustomCa:           "kp3-certificate",
					TlsDownstreamClientCa: "kp4-certificate",
				},
			},
			Settings: &configpb.Settings{
				AutocertCa:           new("kp5-certificate"),
				AutocertTrustedCa:    new("kp6-certificate"),
				CertificateAuthority: new("kp7-certificate"),
				Certificates: []*configpb.Settings_Certificate{
					{CertBytes: []byte("kp8-certificate"), KeyBytes: []byte("kp8-key")},
					{CertBytes: []byte("kp9-certificate"), KeyBytes: []byte("kp9-key")},
				},
				CookieName:      new("s2-cookie"),
				MetricsClientCa: new("kp10-certificate"),
				SshHostKeys: &configpb.Settings_StringList{Values: []string{
					"kp11-certificate",
					"kp12-certificate",
					"kp13-certificate",
				}},
				SshUserCaKey: new("kp14-certificate"),
			},
		}, bundle.Snapshot("test"), protocmp.Transform()))
	})
	t.Run("compiles ppl", func(t *testing.T) {
		t.Parallel()

		bundle := databroker.NewConfigBundle()
		bundle.Policies["p1"] = &configpb.Policy{
			Id:        new("p1"),
			SourcePpl: new(`{}`),
		}
		bundle.Routes["r1"] = &configpb.Route{
			Id:        new("r1"),
			PolicyIds: []string{"p1"},
		}
		cfg := bundle.Snapshot("test")
		if assert.Len(t, cfg.Routes, 1) && assert.Len(t, cfg.Routes[0].Policies, 1) {
			assert.NotEmpty(t, cfg.Routes[0].Policies[0].Rego, "should compile ppl")
		}
	})
	t.Run("adds certificates", func(t *testing.T) {
		t.Parallel()

		cert, err := cryptutil.GenerateCertificate(bytes.Repeat([]byte{0x01}, 32), "example.com", func(c *x509.Certificate) {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		})
		require.NoError(t, err)

		certBS, keyBS, err := cryptutil.EncodeCertificate(cert)
		require.NoError(t, err)

		bundle := databroker.NewConfigBundle()
		bundle.KeyPairs["k1"] = &configpb.KeyPair{
			Certificate: certBS,
			Key:         keyBS,
		}
		cfg := bundle.Snapshot("test")
		if assert.Len(t, cfg.Settings.Certificates, 1) {
			assert.NotEmpty(t, cfg.Settings.Certificates[0].Id)
		}
	})
}
