package e2e

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

// TestMCPMalformedRequestFailsClosed verifies that a POST to an MCP server
// route whose body is not a single well-formed JSON-RPC request is denied by
// authorize and never forwarded to the upstream, even when it names a tool the
// route permits. Authorization of a request it cannot parse must not depend on
// how the upstream parses it.
func TestMCPMalformedRequestFailsClosed(t *testing.T) {
	srv := startMCPEchoOnlyServer(t, upstreams.DialHTTP2)
	ctx := t.Context()

	var exchanges atomic.Int64
	post := func(t testing.TB, body []byte, protocolVersion string) (string, int) {
		t.Helper()
		exchange := fmt.Sprintf("exchange-%d", exchanges.Add(1))
		status, _ := srv.post(ctx, t, exchange, body, protocolVersion)
		return exchange, status
	}

	// A well-formed permitted call through the same path must succeed, or the
	// property below would hold trivially.
	exchange, status := post(t, mustMarshal(t, toolCall("well-formed", "echo")), srv.protocolVersion())
	require.Equal(t, http.StatusOK, status, "well-formed permitted tool call should be accepted")
	_, reached := srv.recorder.get(exchange)
	require.True(t, reached, "well-formed permitted tool call should reach the upstream")

	hegel.Test(t, func(ht *hegel.T) {
		body := drawMalformedRequest(ht)
		// The upstream accepts JSON-RPC batches for 2025-03-26, which is also
		// the version it assumes when the header is missing.
		protocolVersion := hegel.Draw(ht, hegel.SampledFrom([]string{srv.protocolVersion(), "2025-03-26", ""}))
		ht.Logf("MCP-Protocol-Version: %q", protocolVersion)
		ht.Logf("body: %q", body)

		exchange, status := post(ht, body, protocolVersion)
		_, reached := srv.recorder.get(exchange)
		assert.False(ht, reached, "malformed request must not reach the upstream (status %d)", status)
		assert.Equal(ht, http.StatusBadRequest, status, "malformed request should be rejected by authorize, not by policy")
	})

	assert.Zero(t, srv.helloCalls.Load(), "forbidden tool must never run")
}

// TestMCPToolCallMemberNamesAreCaseSensitive verifies that authorize reads
// the tool name the way the upstream does, matching JSON-RPC member names
// case-sensitively, so a member whose name differs only in case cannot make a
// forbidden tool call look like a permitted one.
func TestMCPToolCallMemberNamesAreCaseSensitive(t *testing.T) {
	srv := startMCPEchoOnlyServer(t, upstreams.DialHTTP2)

	call := toolCall("case-variant", "hello")
	call["params"].(map[string]any)["Name"] = "echo"
	srv.post(t.Context(), t, "case-variant", mustMarshal(t, call), srv.protocolVersion())
	_, reached := srv.recorder.get("case-variant")
	assert.False(t, reached, "forbidden tool call must not reach the upstream")
	assert.Zero(t, srv.helloCalls.Load(), "forbidden tool must not run")
}

// drawMalformedRequest draws a body that is not a single well-formed JSON-RPC
// request, derived from a tools/call of either the permitted or the forbidden
// tool.
func drawMalformedRequest(ht *hegel.T) []byte {
	tool := hegel.Draw(ht, hegel.SampledFrom([]string{"echo", "hello"}))
	call := toolCall("malformed", tool)

	switch kind := hegel.Draw(ht, hegel.SampledFrom([]string{
		"truncated",
		"trailing data",
		"batch",
		"not an object",
		"bad version",
		"bad id",
		"bad method",
		"bad params",
		"bad tool name",
		"bad arguments",
	})); kind {
	case "truncated":
		// Every strict prefix of a compact JSON object is invalid JSON.
		valid := mustMarshal(ht, call)
		return valid[:hegel.Draw(ht, hegel.Integers(0, len(valid)-1))]
	case "trailing data":
		suffix := hegel.Draw(ht, hegel.SampledFrom([]string{"x", "{", "}", "[", "]", ",", "0", `"`})) +
			hegel.Draw(ht, hegel.Text())
		return append(mustMarshal(ht, call), suffix...)
	case "batch":
		batch := make([]any, hegel.Draw(ht, hegel.Integers(1, 3)))
		for i := range batch {
			batch[i] = toolCall(fmt.Sprintf("batch-%d", i), hegel.Draw(ht, hegel.SampledFrom([]string{"echo", "hello"})))
		}
		return mustMarshal(ht, batch)
	case "not an object":
		return mustMarshal(ht, hegel.Draw(ht, hegel.OneOf(jsonScalars(), jsonArrays())))
	case "bad version":
		if hegel.Draw(ht, hegel.Booleans()) {
			delete(call, "jsonrpc")
		} else {
			call["jsonrpc"] = hegel.Draw(ht, hegel.Filter(jsonValues(), func(v any) bool { return v != "2.0" }))
		}
	case "bad id":
		call["id"] = hegel.Draw(ht, hegel.OneOf(jsonBooleans(), jsonArrays(), jsonObjects()))
	case "bad method":
		call["method"] = hegel.Draw(ht, hegel.OneOf(jsonNull(), jsonBooleans(), jsonNumbers(), jsonArrays(), jsonObjects()))
	case "bad params":
		call["params"] = hegel.Draw(ht, hegel.OneOf(jsonBooleans(), jsonNumbers(), jsonStrings(), jsonArrays()))
	case "bad tool name":
		call["params"].(map[string]any)["name"] = hegel.Draw(ht, hegel.OneOf(jsonNull(), jsonBooleans(), jsonNumbers(), jsonArrays(), jsonObjects()))
	case "bad arguments":
		call["params"].(map[string]any)["arguments"] = hegel.Draw(ht, hegel.OneOf(jsonBooleans(), jsonNumbers(), jsonStrings(), jsonArrays()))
	default:
		ht.Fatalf("unknown malformation %q", kind)
	}
	return mustMarshal(ht, call)
}

func jsonNull() hegel.Generator[any] { return hegel.Just[any](nil) }

func jsonBooleans() hegel.Generator[any] {
	return hegel.Map(hegel.Booleans(), func(b bool) any { return b })
}

func jsonNumbers() hegel.Generator[any] {
	return hegel.Map(hegel.Floats[float64]().AllowNaN(false).AllowInfinity(false), func(f float64) any { return f })
}

func jsonStrings() hegel.Generator[any] {
	return hegel.Map(hegel.Text(), func(s string) any { return s })
}

func jsonScalars() hegel.Generator[any] {
	return hegel.OneOf(jsonNull(), jsonBooleans(), jsonNumbers(), jsonStrings())
}

// jsonArrays and jsonObjects never produce nil, which would marshal as null.

func jsonArrays() hegel.Generator[any] {
	return hegel.Map(hegel.Lists(jsonScalars()).MaxSize(3), func(xs []any) any { return append([]any{}, xs...) })
}

func jsonObjects() hegel.Generator[any] {
	return hegel.Map(hegel.Maps(hegel.Text(), jsonScalars()).MaxSize(3), func(m map[string]any) any {
		if m == nil {
			m = map[string]any{}
		}
		return m
	})
}

func jsonValues() hegel.Generator[any] {
	return hegel.OneOf(jsonScalars(), jsonArrays(), jsonObjects())
}
