package webauthnutil

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEffectiveDomain(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in     string
		expect string
	}{
		{"https://www.example.com/some/path", "example.com"},
		{"https://www.example.com:8080/some/path", "example.com"},
		{"https://www.subdomain.example.com/some/path", "example.com"},
		{"https://example.com/some/path", "example.com"},
	} {
		t.Run(tc.expect, func(t *testing.T) {
			t.Parallel()

			r, err := http.NewRequest(http.MethodGet, tc.in, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.expect, GetEffectiveDomain(r))
		})
	}
}
