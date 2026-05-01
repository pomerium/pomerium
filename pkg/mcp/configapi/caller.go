package configapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// dynamicCaller makes Connect unary RPC calls using JSON encoding against an
// in-process http.Handler. It intentionally avoids typed Connect clients: the
// MCP tool input/output matches the protobuf JSON representation and we pass
// bytes straight through.
type dynamicCaller struct {
	handler http.Handler
	stamps  []func(*http.Request)
}

func newDynamicCaller(handler http.Handler, stamps []func(*http.Request)) *dynamicCaller {
	return &dynamicCaller{handler: handler, stamps: stamps}
}

// call executes a Connect unary RPC on the in-process handler.
// inputJSON is the raw JSON from MCP tool arguments (matches the protobuf JSON schema).
// perCallHeaders are applied after the configured stamps and replace any
// matching keys, so per-call PreCall values authoritatively override static
// stamps; nil is a no-op.
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
	for _, stamp := range c.stamps {
		stamp(req)
	}
	for k, vs := range perCallHeaders {
		req.Header[k] = vs
	}

	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	// ListRoutes / ListPolicies responses on large clusters can exceed tens of
	// MiB; cap generously rather than silently truncating.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseConnectError(resp.StatusCode, body)
	}

	return body, nil
}

// parseConnectError returns a typed *connect.Error built from the JSON body
// produced by connect-go for non-OK responses, so callers can match on Code()
// via errors.As. Falls back to a plain HTTP error if the body isn't a wire
// connect error.
func parseConnectError(statusCode int, body []byte) error {
	var wire struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &wire); err == nil && wire.Message != "" {
		return connect.NewError(connectCodeFromWire(wire.Code), errors.New(wire.Message))
	}
	return fmt.Errorf("HTTP %d: %s", statusCode, string(body))
}

// connectCodeFromWire maps the JSON `code` string emitted by connect-go to a
// typed connect.Code. Unknown values fall back to CodeUnknown.
func connectCodeFromWire(code string) connect.Code {
	switch code {
	case "canceled":
		return connect.CodeCanceled
	case "unknown":
		return connect.CodeUnknown
	case "invalid_argument":
		return connect.CodeInvalidArgument
	case "deadline_exceeded":
		return connect.CodeDeadlineExceeded
	case "not_found":
		return connect.CodeNotFound
	case "already_exists":
		return connect.CodeAlreadyExists
	case "permission_denied":
		return connect.CodePermissionDenied
	case "resource_exhausted":
		return connect.CodeResourceExhausted
	case "failed_precondition":
		return connect.CodeFailedPrecondition
	case "aborted":
		return connect.CodeAborted
	case "out_of_range":
		return connect.CodeOutOfRange
	case "unimplemented":
		return connect.CodeUnimplemented
	case "internal":
		return connect.CodeInternal
	case "unavailable":
		return connect.CodeUnavailable
	case "data_loss":
		return connect.CodeDataLoss
	case "unauthenticated":
		return connect.CodeUnauthenticated
	default:
		return connect.CodeUnknown
	}
}
