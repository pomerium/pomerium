package agentic

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeJSONBodyBoundsTheBody pins the bound that has to hold BEFORE
// decoding. Every other limit on a run request is checked on the decoded value,
// so without this an authenticated workload could make the AS read and allocate
// an arbitrarily large body on its way to a 400.
func TestDecodeJSONBodyBoundsTheBody(t *testing.T) {
	t.Parallel()

	newRequest := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/agentic/runs", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	}

	t.Run("an ordinary request decodes", func(t *testing.T) {
		var req createRunRequest
		err := decodeJSONBody(httptest.NewRecorder(), newRequest(`{"prompt":"do the thing"}`), &req)
		require.NoError(t, err)
		assert.Equal(t, "do the thing", req.Prompt)
	})

	t.Run("an oversized body is refused, not decoded", func(t *testing.T) {
		// Valid JSON, and a prompt the decoded-value checks would reject anyway —
		// the point is that it never gets that far.
		body := fmt.Sprintf(`{"prompt":%q}`, strings.Repeat("A", maxRequestBytes*2))
		require.Greater(t, len(body), maxRequestBytes)

		var req createRunRequest
		err := decodeJSONBody(httptest.NewRecorder(), newRequest(body), &req)
		require.Error(t, err, "a body over the limit must not decode")

		var tooLarge *http.MaxBytesError
		require.True(t, errors.As(err, &tooLarge),
			"the error must be a MaxBytesError so the handler can answer 413, got %T: %v", err, err)
		assert.Equal(t, int64(maxRequestBytes), tooLarge.Limit)
		assert.Empty(t, req.Prompt, "nothing may be populated from a refused body")
	})
}
