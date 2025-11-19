package hosted_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/identity/oidc/hosted"
)

func TestDeriveProviderInfo(t *testing.T) {
	t.Run("invalid authenticate service URL", func(t *testing.T) {
		err := hosted.DeriveProviderInfo(nil, &config.Options{
			AuthenticateURLString: "foobar",
		})
		assert.ErrorContains(t, err, "url does not contain a valid scheme")
	})
	t.Run("empty shared secret", func(t *testing.T) {
		err := hosted.DeriveProviderInfo(nil, &config.Options{})
		assert.ErrorContains(t, err, "empty shared secret")
	})
	t.Run("ok", func(t *testing.T) {
		var idp identity.Provider
		err := hosted.DeriveProviderInfo(&idp, &config.Options{
			AuthenticateURLString: "https://client.example.com",
			SharedKey:             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32)),
		})
		expectedKey, _ := base64.RawStdEncoding.DecodeString(
			"XDQoBGE41Nct7vr1PGAR4PXI125iGjRY31YzNDmDF5VSZkmQAX/2AXwhchudEEL7UHVHuFlTvuFuOv7UFktKCg")
		assert.NoError(t, err)
		assert.Equal(t, "https://client.example.com", idp.ClientId)
		assert.Equal(t, string(expectedKey), idp.ClientSecret)
		assert.Equal(t, "https://authenticate.pomerium.app", idp.Url)
	})
	t.Run("provider URL already set", func(t *testing.T) {
		idp := identity.Provider{
			Url: "https://some-other-provider.example.com",
		}
		err := hosted.DeriveProviderInfo(&idp, &config.Options{
			AuthenticateURLString: "https://client.example.com",
			SharedKey:             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 32)),
		})
		assert.NoError(t, err)
		assert.Equal(t, "https://some-other-provider.example.com", idp.Url)
	})
}
