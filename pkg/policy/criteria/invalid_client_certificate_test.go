package criteria

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvalidClientCertificate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		input    Input
		expected A
	}{
		{
			"not presented",
			Input{},
			A{true, A{ReasonClientCertificateRequired}, M{}},
		},
		{
			"invalid",
			Input{
				HTTP: InputHTTP{
					ClientCertificate: ClientCertificateInfo{Presented: true},
				},
			},
			A{true, A{ReasonInvalidClientCertificate}, M{}},
		},
		{
			"valid",
			Input{
				HTTP: InputHTTP{
					ClientCertificate: ClientCertificateInfo{Presented: true},
				},
				IsValidClientCertificate: true,
			},
			A{false, A{ReasonValidClientCertificate}, M{}},
		},
	}

	const policy = `
deny:
  or:
    - invalid_client_certificate: true`

	for i := range cases {
		c := cases[i]
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()

			res, err := evaluate(t, policy, []dataBrokerRecord{}, c.input)
			require.NoError(t, err)
			assert.Equal(t, A{false, A{}}, res["allow"])
			assert.Equal(t, c.expected, res["deny"])
		})
	}
}
