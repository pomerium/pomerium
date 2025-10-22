package criteria

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestHTTPMethod(t *testing.T) {
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - http_method:
        is: GET
`, []*databroker.Record{}, Input{HTTP: InputHTTP{Method: http.MethodGet}})
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
`, []*databroker.Record{}, Input{HTTP: InputHTTP{Method: "POST"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonHTTPMethodUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
