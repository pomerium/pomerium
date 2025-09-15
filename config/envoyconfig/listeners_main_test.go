package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func Test_requireProxyProtocol(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil, true)
	t.Run("required", func(t *testing.T) {
		li, err := b.buildMainListener(t.Context(), &config.Config{Options: &config.Options{
			UseProxyProtocol: true,
			InsecureServer:   true,
		}}, false, false)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `[
			{
				"name": "envoy.filters.listener.proxy_protocol",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol"
				}
			}
		]`, li.GetListenerFilters())
	})
	t.Run("not required", func(t *testing.T) {
		li, err := b.buildMainListener(t.Context(), &config.Config{Options: &config.Options{
			UseProxyProtocol: false,
			InsecureServer:   true,
		}}, false, false)
		require.NoError(t, err)
		assert.Len(t, li.GetListenerFilters(), 0)
	})
	t.Run("disabled for quic", func(t *testing.T) {
		li, err := b.buildMainListener(t.Context(), &config.Config{Options: &config.Options{
			SharedKey:        cryptutil.NewBase64Key(),
			UseProxyProtocol: true,
			CodecType:        config.CodecTypeHTTP3,
		}}, false, true)
		require.NoError(t, err)
		assert.Len(t, li.GetListenerFilters(), 0)
	})
}
