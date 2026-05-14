package configapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// maxResponseBytes caps the size of any response read by dynamicCaller.
// Paired with maxListResults (=100) in registry.go: a 100-entry
// ListRoutesResponse with full per-route policy bodies fits comfortably
// under this. Anything larger means a missing pagination clamp or a
// misbehaving caller; failing loudly is preferable to buffering hundreds
// of MiB into RAM.
const maxResponseBytes int64 = 5 << 20

// dynamicCaller makes Connect unary RPC calls using JSON encoding against an
// in-process http.Handler. It intentionally avoids typed Connect clients: the
// MCP tool input/output matches the protobuf JSON representation and we pass
// bytes straight through.
type dynamicCaller struct {
	handler   http.Handler
	modifiers []RequestModifier
}

func newDynamicCaller(handler http.Handler, modifiers []RequestModifier) *dynamicCaller {
	return &dynamicCaller{handler: handler, modifiers: modifiers}
}

// call executes a Connect unary RPC on the in-process handler.
// inputJSON is the raw JSON from MCP tool arguments (matches the protobuf JSON schema).
// perCallHeaders are applied after the configured modifiers and replace any
// matching keys, so per-call PreCall values authoritatively override static
// modifiers; nil is a no-op.
// Returns the response as JSON bytes.
func (c *dynamicCaller) call(
	ctx context.Context,
	method protoreflect.MethodDescriptor,
	inputJSON json.RawMessage,
	perCallHeaders http.Header,
) (json.RawMessage, error) {
	url := "/" + string(method.Parent().FullName()) + "/" + string(method.Name())

	if len(inputJSON) == 0 {
		inputJSON = []byte("{}")
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(inputJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	for _, mod := range c.modifiers {
		if err := mod(req); err != nil {
			return nil, fmt.Errorf("modifying request: %w", err)
		}
	}
	maps.Copy(req.Header, perCallHeaders)

	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	// Read up to maxResponseBytes+1 so we can distinguish "right at the cap"
	// from "exceeds the cap". Anything over fails loudly with a hint at the
	// pagination clamp.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d-byte cap (paginate with limit ≤ %d)",
			maxResponseBytes, maxListResults)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseConnectError(resp.StatusCode, body)
	}

	return body, nil
}

// parseConnectError returns a typed *connect.Error built from the JSON
// body produced by connect-go for non-OK responses, so callers can match
// on Code() via errors.As. Code parsing delegates to Code.UnmarshalText —
// connect-go's own wire-format decoder — rather than a hand-maintained
// switch that has to be kept in sync with the connect.Code enum. The
// resulting error is constructed via NewWireError because it represents a
// failure produced by the (in-process) server, which is the documented
// purpose of that constructor. Falls back to a plain HTTP error when the
// body isn't a wire connect error.
func parseConnectError(statusCode int, body []byte) error {
	var wire struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &wire); err == nil && wire.Code != "" {
		var code connect.Code
		if err := code.UnmarshalText([]byte(wire.Code)); err != nil {
			// Unknown wire code (e.g. forward-compat from a future
			// connect-go). Surface the unrecognised name in the error
			// message rather than silently downgrading to a typed
			// CodeUnknown that might match the wrong ErrorMapper.
			return fmt.Errorf("HTTP %d: connect error with unknown code %q: %s",
				statusCode, wire.Code, wire.Message)
		}
		msg := wire.Message
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", statusCode)
		}
		return connect.NewWireError(code, errors.New(msg))
	}
	return fmt.Errorf("HTTP %d: %s", statusCode, string(body))
}
