package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestHTTPPath(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - http_path:
        is: /test
`, []*databroker.Record{}, input.PolicyRequest{HTTP: input.RequestHTTP{Path: "/test"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonHTTPPathOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - http_path:
        is: /test
`, []*databroker.Record{}, input.PolicyRequest{HTTP: input.RequestHTTP{Path: "/not-test"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonHTTPPathUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
