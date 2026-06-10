package protoutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestRedactSensitive_Scalars(t *testing.T) {
	t.Parallel()

	settings := &configpb.Settings{
		SharedSecret: new("shared-secret-value"),
		CookieSecret: new("cookie-secret-value"),
		CookieName:   new("my-cookie"),
	}
	protoutil.RedactSensitive(settings)

	assert.Equal(t, "[REDACTED]", settings.GetSharedSecret())
	assert.Equal(t, "[REDACTED]", settings.GetCookieSecret())
	assert.Equal(t, "my-cookie", settings.GetCookieName(), "non-sensitive fields must be left intact")
}

func TestRedactSensitive_NestedMessages(t *testing.T) {
	t.Parallel()

	cfg := &configpb.Config{
		Name: "test-config",
		Settings: &configpb.Settings{
			SharedSecret:         new("shared-secret-value"),
			CertificateAuthority: new("not-a-secret"),
		},
		Routes: []*configpb.Route{{
			From:         "https://from.example.com",
			TlsClientKey: "tls-client-key-value",
		}},
	}
	protoutil.RedactSensitive(cfg)

	assert.Equal(t, "test-config", cfg.GetName())
	assert.Equal(t, "[REDACTED]", cfg.GetSettings().GetSharedSecret())
	assert.Equal(t, "not-a-secret", cfg.GetSettings().GetCertificateAuthority())
	assert.Equal(t, "[REDACTED]", cfg.GetRoutes()[0].GetTlsClientKey())
	assert.Equal(t, "https://from.example.com", cfg.GetRoutes()[0].GetFrom())
}

func TestRedactSensitive_Bytes(t *testing.T) {
	t.Parallel()

	settings := &configpb.Settings{
		Certificates: []*configpb.Settings_Certificate{{
			CertBytes: []byte("public-cert"),
			KeyBytes:  []byte("private-key-bytes"),
		}},
	}
	protoutil.RedactSensitive(settings)

	assert.Equal(t, []byte("public-cert"), settings.GetCertificates()[0].GetCertBytes())
	assert.Equal(t, []byte("[REDACTED]"), settings.GetCertificates()[0].GetKeyBytes())
}

func TestRedactSensitive_MessageKindCleared(t *testing.T) {
	t.Parallel()

	// ssh_host_keys is a sensitive message-kind field (StringList) carrying
	// inline SSH host private keys: no placeholder representation exists, so
	// it must be cleared entirely.
	settings := &configpb.Settings{
		SshHostKeys: &configpb.Settings_StringList{
			Values: []string{"-----BEGIN PRIVATE KEY-----"},
		},
		SshUserCaKey: new("ssh-user-ca-private-key"),
	}
	protoutil.RedactSensitive(settings)

	assert.Nil(t, settings.GetSshHostKeys(),
		"sensitive message-kind fields must be cleared, not recursed")
	assert.Equal(t, "[REDACTED]", settings.GetSshUserCaKey())
}

func TestRedactSensitive_DescendsIntoAny(t *testing.T) {
	t.Parallel()

	cfg := &configpb.Config{
		Settings: &configpb.Settings{
			SharedSecret: new("shared-secret-value"),
		},
	}
	data, err := anypb.New(cfg)
	require.NoError(t, err)
	record := &databrokerpb.Record{
		Type: protoutil.GetTypeURL(cfg),
		Id:   "test-id",
		Data: data,
	}
	protoutil.RedactSensitive(record)

	var got configpb.Config
	require.NoError(t, record.GetData().UnmarshalTo(&got))
	assert.Equal(t, "[REDACTED]", got.GetSettings().GetSharedSecret())
	assert.Equal(t, "test-id", record.GetId())
}

func TestRedactSensitive_UnknownAnyTypeLeftIntact(t *testing.T) {
	t.Parallel()

	record := &databrokerpb.Record{
		Type: "type.googleapis.com/not.a.RealType",
		Id:   "test-id",
		Data: &anypb.Any{
			TypeUrl: "type.googleapis.com/not.a.RealType",
			Value:   []byte("opaque"),
		},
	}
	protoutil.RedactSensitive(record)

	assert.Equal(t, []byte("opaque"), record.GetData().GetValue())
}

func TestRedactSensitive_Nil(t *testing.T) {
	t.Parallel()

	assert.NotPanics(t, func() {
		protoutil.RedactSensitive(nil)
		protoutil.RedactSensitive((*configpb.Settings)(nil))
	})
}

func TestRedactSensitive_NonMessageWrapper(t *testing.T) {
	t.Parallel()

	// messages without any sensitive fields pass through unchanged
	v := wrapperspb.String("hello")
	protoutil.RedactSensitive(v)
	assert.Equal(t, "hello", v.GetValue())
}
