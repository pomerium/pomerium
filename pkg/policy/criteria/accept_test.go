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
	require.Equal(t, true, res["allow"])
	require.Equal(t, false, res["deny"])
}
