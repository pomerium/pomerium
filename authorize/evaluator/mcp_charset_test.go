package evaluator

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRequestMCPFromCheckRequestCharset verifies that a POST is accepted when
// its Content-Type has no charset or a UTF-8 charset, and rejected when it has
// any other.
func TestRequestMCPFromCheckRequestCharset(t *testing.T) {
	t.Parallel()

	for contentType, wantErr := range map[string]bool{
		"application/json":                     false,
		"application/json; charset=utf-8":      false,
		"application/json; charset=UTF-8":      false,
		"application/json; charset=utf8":       false,
		"application/json; charset=utf-7":      true,
		"application/json; charset=iso-8859-1": true,
		`application/json; charset=""`:         true,
	} {
		_, err := RequestMCPFromCheckRequest(mcpCheckRequest(http.MethodPost,
			map[string]string{"content-type": contentType}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		assert.Equal(t, wantErr, err != nil, "%s: %v", contentType, err)
	}
}
