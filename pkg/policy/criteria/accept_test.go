package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccept(t *testing.T) {
	res, err := evaluate(t, `
allow:
  and:
    - accept: 1
`, []dataBrokerRecord{}, Input{})
	require.NoError(t, err)
	require.Equal(t, A{true, A{ReasonAccept}, M{}}, res["allow"])
	require.Equal(t, A{false, A{}}, res["deny"])
}
