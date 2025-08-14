package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestSourceIPs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip:
        is: "127.0.0.1"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "127.0.0.1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonSourceIPOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - source_ip:
        is: "127.0.0.1"
`, []*databroker.Record{}, Input{HTTP: InputHTTP{IP: "192.168.1.1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonSourceIPUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
