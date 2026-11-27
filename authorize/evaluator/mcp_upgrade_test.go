package evaluator

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRequestMCPFromCheckRequestUpgrade verifies that a request with an
// Upgrade header is rejected, and that the same request without it is
// accepted.
func TestRequestMCPFromCheckRequestUpgrade(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
	} {
		headers := map[string]string{"content-type": "application/json"}
		_, err := RequestMCPFromCheckRequest(mcpCheckRequest(tc.method, headers, tc.body))
		assert.NoError(t, err, tc.method)

		headers["connection"] = "Upgrade"
		headers["upgrade"] = "websocket"
		_, err = RequestMCPFromCheckRequest(mcpCheckRequest(tc.method, headers, tc.body))
		assert.Error(t, err, tc.method)
	}
}
