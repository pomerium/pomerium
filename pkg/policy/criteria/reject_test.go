package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestReject(t *testing.T) {
	t.Parallel()

	res, err := evaluate(t, `
allow:
  and:
    - reject: 1
`, []*databroker.Record{}, Input{})
	require.NoError(t, err)
	require.Equal(t, A{false, A{ReasonReject}, M{}}, res["allow"])
	require.Equal(t, A{false, A{}}, res["deny"])
}
