package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCORSPreflight(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - cors_preflight: 1
`, []dataBrokerRecord{}, Input{HTTP: InputHTTP{
			Method: "OPTIONS",
			Headers: map[string][]string{
				"Access-Control-Request-Method": {"GET"},
				"Origin":                        {"example.com"},
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
`, []dataBrokerRecord{}, Input{HTTP: InputHTTP{
			Method: "OPTIONS",
		}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{"non-cors-request"}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
