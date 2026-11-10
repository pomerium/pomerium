package envoyconfig

import (
	"math"
	"testing"

	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerFilterConfigExtAuthzContextExtensionsWithBody(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		maxRequestBytes uint32
		expect          uint32
	}{
		{4096, 4097},
		{math.MaxUint32, math.MaxUint32},
	} {
		var perRoute envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute
		require.NoError(t, PerFilterConfigExtAuthzContextExtensionsWithBody(tc.maxRequestBytes, nil).UnmarshalTo(&perRoute))
		bufferSettings := perRoute.GetCheckSettings().GetWithRequestBody()
		assert.Equal(t, tc.expect, bufferSettings.GetMaxRequestBytes())
		assert.False(t, bufferSettings.GetAllowPartialMessage())
	}
}
