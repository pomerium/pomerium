package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPMethod(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - http_method:
        is: GET
`, []dataBrokerRecord{}, Input{HTTP: InputHTTP{Method: "GET"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonHTTPMethodOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - http_method:
        is: GET
`, []dataBrokerRecord{}, Input{HTTP: InputHTTP{Method: "POST"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonHTTPMethodUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
