package criteria

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestCORSPreflight(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - cors_preflight: 1
`, nil, input.PolicyRequest{HTTP: input.RequestHTTP{
			Method: "OPTIONS",
			Headers: map[string]string{
				"Access-Control-Request-Method": http.MethodGet,
				"Origin":                        "example.com",
			},
		}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{"cors-request"}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("false", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - cors_preflight: 1
`, nil, input.PolicyRequest{HTTP: input.RequestHTTP{
			Method: "OPTIONS",
		}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{"non-cors-request"}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
