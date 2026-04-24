package configapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

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
// Returns the response as JSON bytes.
func (c *dynamicCaller) call(
	ctx context.Context,
	method protoreflect.MethodDescriptor,
	inputJSON json.RawMessage,
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

func parseConnectError(statusCode int, body []byte) error {
	var connectErr struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &connectErr); err == nil && connectErr.Message != "" {
		return fmt.Errorf("%s: %s", connectErr.Code, connectErr.Message)
	}
	return fmt.Errorf("HTTP %d: %s", statusCode, string(body))
}
