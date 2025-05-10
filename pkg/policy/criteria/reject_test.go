package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestReject(t *testing.T) {
	res, err := evaluate(t, `
allow:
  and:
    - reject: 1
`, []*databroker.Record{}, input.PolicyRequest{})
	require.NoError(t, err)
	require.Equal(t, A{false, A{ReasonReject}, M{}}, res["allow"])
	require.Equal(t, A{false, A{}}, res["deny"])
}
