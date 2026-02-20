package databroker

import (
	"crypto/tls"
	"crypto/x509"
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// A ConfigBundle is a collection of config entities stored in the databroker.
type ConfigBundle struct {
	KeyPairs map[string]*configpb.KeyPair
	Policies map[string]*configpb.Policy
	Routes   map[string]*configpb.Route
	Settings map[string]*configpb.Settings
}

// NewConfigBundle creates a new ConfigBundle.
func NewConfigBundle() *ConfigBundle {
	return &ConfigBundle{
		KeyPairs: make(map[string]*configpb.KeyPair),
		Policies: make(map[string]*configpb.Policy),
		Routes:   make(map[string]*configpb.Route),
		Settings: make(map[string]*configpb.Settings),
	}
}

// Snapshot takes a config bundle and converts it into a combined, denormalized
// config snapshot.
func (bundle *ConfigBundle) Snapshot(name string) *configpb.Config {
	return &configpb.Config{
		Name:     name,
		Routes:   bundle.snapshotAllRoutes(),
		Settings: bundle.snapshotAllSettings(),
	}
}

func (bundle *ConfigBundle) snapshotAllRoutes() []*configpb.Route {
	var routes []*configpb.Route
	routeIDs := slices.Sorted(maps.Keys(bundle.Routes))
	for _, routeID := range routeIDs {
		routes = append(routes, bundle.snapshotRoute(bundle.Routes[routeID]))
	}
	return routes
}

func (bundle *ConfigBundle) snapshotAllSettings() *configpb.Settings {
	settings := new(configpb.Settings)
	settingsIDs := slices.Sorted(maps.Keys(bundle.Settings))
	for _, settingsID := range settingsIDs {
		proto.Merge(settings, bundle.snapshotSettings(bundle.Settings[settingsID]))
	}

	// add server certificates
	for _, kp := range bundle.KeyPairs {
		cert, err := tls.X509KeyPair(kp.GetCertificate(), kp.GetKey())
		// ignore invalid certificates
		if err != nil {
			continue
		}
		// only add server certificates
		if !slices.Contains(cert.Leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			continue
		}
		settings.Certificates = append(settings.Certificates, &configpb.Settings_Certificate{
			CertBytes: kp.GetCertificate(),
			KeyBytes:  kp.GetKey(),
			Id:        kp.GetId(),
		})
	}

	return settings
}

func (bundle *ConfigBundle) snapshotPolicy(src *configpb.Policy) *configpb.Policy {
	dst := proto.CloneOf(src)

	// clear computed properties
	dst.AssignedRoutes = nil
	dst.CreatedAt = nil
	dst.EnforcedRoutes = nil
	dst.ModifiedAt = nil
	dst.NamespaceName = nil

	return dst
}

func (bundle *ConfigBundle) snapshotRoute(src *configpb.Route) *configpb.Route {
	dst := proto.CloneOf(src)

	// clear computed properties
	dst.AssignedPolicies = nil
	dst.CreatedAt = nil
	dst.EnforcedPolicies = nil
	dst.ModifiedAt = nil
	dst.NamespaceName = nil

	// populate key pair references
	if keyPairID := dst.KubernetesServiceAccountTokenKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.KubernetesServiceAccountToken = string(keyPair.Key)
		} else {
			log.Error().
				Str("route-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: kubernetes service account token key pair not found for route")
		}
		dst.KubernetesServiceAccountTokenKeyPairId = nil
	}
	if keyPairID := dst.TlsClientKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.TlsClientCert = string(keyPair.GetCertificate())
			dst.TlsClientKey = string(keyPair.GetKey())
		} else {
			log.Error().
				Str("route-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: tls client key pair not found for route")
		}
		dst.TlsClientKeyPairId = nil
	}
	if keyPairID := dst.TlsCustomCaKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.TlsCustomCa = string(keyPair.GetCertificate())
		} else {
			log.Error().
				Str("route-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: tls custom ca key pair not found for route")
		}
		dst.TlsCustomCaKeyPairId = nil
	}
	if keyPairID := dst.TlsDownstreamClientCaKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.TlsDownstreamClientCa = string(keyPair.GetCertificate())
		} else {
			log.Error().
				Str("route-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: tls downstream client ca key pair not found for route")
		}
		dst.TlsDownstreamClientCaKeyPairId = nil
	}

	// snapshot any policies
	for i := range bundle.Policies {
		bundle.Policies[i] = bundle.snapshotPolicy(bundle.Policies[i])
	}

	// populate policy references
	for _, policyID := range dst.GetPolicyIds() {
		policy, ok := bundle.Policies[policyID]
		if ok {
			dst.Policies = append(dst.Policies, bundle.snapshotPolicy(policy))
		} else {
			log.Error().
				Str("route-id", dst.GetId()).
				Str("policy-id", policyID).
				Msg("databroker/config-bundle-snapshot: policy not found for route")
		}
	}
	dst.PolicyIds = nil

	return dst
}

func (bundle *ConfigBundle) snapshotSettings(src *configpb.Settings) *configpb.Settings {
	dst := proto.CloneOf(src)

	// clear computed properties
	dst.CreatedAt = nil
	dst.ModifiedAt = nil

	// populate key pair references
	if keyPairID := dst.AutocertCaKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.AutocertCa = proto.String(string(keyPair.Certificate))
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: autocert ca key pair not found for settings")
		}
		dst.AutocertCaKeyPairId = nil
	}
	if keyPairID := dst.AutocertTrustedCaKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.AutocertTrustedCa = proto.String(string(keyPair.Certificate))
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: autocert trusted ca key pair not found for settings")
		}
		dst.AutocertTrustedCaKeyPairId = nil
	}
	if keyPairID := dst.CertificateAuthorityKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.CertificateAuthority = proto.String(string(keyPair.Certificate))
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: certificate authority key pair not found for settings")
		}
		dst.CertificateAuthorityKeyPairId = nil
	}
	for _, keyPairID := range dst.CertificateKeyPairIds {
		keyPair, ok := bundle.KeyPairs[keyPairID]
		if ok {
			dst.Certificates = append(dst.Certificates, &configpb.Settings_Certificate{
				CertBytes: keyPair.Certificate,
				KeyBytes:  keyPair.Key,
			})
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", keyPairID).
				Msg("databroker/config-bundle-snapshot: certificate key pair not found for settings")
		}
	}
	dst.CertificateKeyPairIds = nil
	if keyPairID := dst.MetricsClientCaKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.MetricsClientCa = proto.String(string(keyPair.Certificate))
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: metrics client ca key pair not found for settings")
		}
		dst.MetricsClientCaKeyPairId = nil
	}
	for _, keyPairID := range dst.SshHostKeyPairIds {
		keyPair, ok := bundle.KeyPairs[keyPairID]
		if ok {
			if dst.SshHostKeys == nil {
				dst.SshHostKeys = &configpb.Settings_StringList{}
			}
			dst.SshHostKeys.Values = append(dst.SshHostKeys.Values, string(keyPair.Certificate))
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", keyPairID).
				Msg("databroker/config-bundle-snapshot: ssh host key pair not found for settings")
		}
	}
	dst.SshHostKeyPairIds = nil
	if keyPairID := dst.SshUserCaKeyPairId; keyPairID != nil {
		keyPair, ok := bundle.KeyPairs[*keyPairID]
		if ok {
			dst.SshUserCaKey = proto.String(string(keyPair.Certificate))
		} else {
			log.Error().
				Str("settings-id", dst.GetId()).
				Str("key-pair-id", *keyPairID).
				Msg("databroker/config-bundle-snapshot: ssh user ca key pair not found for settings")
		}
		dst.SshUserCaKeyPairId = nil
	}
	return dst
}
