package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPPath(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - http_path:
        is: /test
`, []dataBrokerRecord{}, Input{HTTP: InputHTTP{Path: "/test"}})
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
`, []dataBrokerRecord{}, Input{HTTP: InputHTTP{Path: "/not-test"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonHTTPPathUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
