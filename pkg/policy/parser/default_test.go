package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddDefaultClientCertificateRule(t *testing.T) {
	t.Parallel()

	var p Policy
	p.AddDefaultClientCertificateRule()
	assert.Equal(t, Policy{
		Rules: []Rule{{
			Action: ActionDeny,
			Or: []Criterion{
				{Name: "invalid_client_certificate"},
			},
		}},
	}, p)
}
