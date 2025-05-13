package criteria

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestInvalidClientCertificate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		input    input.PolicyRequest
		expected A
	}{
		{
			"not presented",
			input.PolicyRequest{},
			A{true, A{ReasonClientCertificateRequired}, M{}},
		},
		{
			"invalid",
			input.PolicyRequest{
				HTTP: input.RequestHTTP{
					ClientCertificate: input.ClientCertificateInfo{Presented: true},
				},
			},
			A{true, A{ReasonInvalidClientCertificate}, M{}},
		},
		{
			"valid",
			input.PolicyRequest{
				HTTP: input.RequestHTTP{
					ClientCertificate: input.ClientCertificateInfo{Presented: true},
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

			res, err := evaluate(t, policy, []*databroker.Record{}, c.input)
			require.NoError(t, err)
			assert.Equal(t, A{false, A{}}, res["allow"])
			assert.Equal(t, c.expected, res["deny"])
		})
	}
}
