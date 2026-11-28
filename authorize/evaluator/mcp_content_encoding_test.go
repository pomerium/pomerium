package evaluator

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRequestMCPFromCheckRequestContentEncoding verifies that a POST is
// accepted when it has no Content-Encoding or the identity coding, and
// rejected when it names any other content coding.
func TestRequestMCPFromCheckRequestContentEncoding(t *testing.T) {
	t.Parallel()

	post := func(headers map[string]string) error {
		headers["content-type"] = "application/json"
		_, err := RequestMCPFromCheckRequest(mcpCheckRequest(http.MethodPost, headers, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		return err
	}

	assert.NoError(t, post(map[string]string{}))
	assert.NoError(t, post(map[string]string{"content-encoding": "identity"}))
	for _, coding := range []string{"gzip", "deflate", "br", "zstd", "identity, br"} {
		assert.Error(t, post(map[string]string{"content-encoding": coding}), coding)
	}
}
