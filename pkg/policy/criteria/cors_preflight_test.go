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
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
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
		require.Equal(t, false, res["allow"])
		require.Equal(t, false, res["deny"])
	})
}
