package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReject(t *testing.T) {
	res, err := evaluate(t, `
allow:
  and:
    - reject: 1
`, []dataBrokerRecord{}, Input{})
	require.NoError(t, err)
	require.Equal(t, A{false, A{ReasonReject}, M{}}, res["allow"])
	require.Equal(t, A{false, A{}}, res["deny"])
}
