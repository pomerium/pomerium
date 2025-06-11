package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func Test_requireProxyProtocol(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil, true)
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
}
