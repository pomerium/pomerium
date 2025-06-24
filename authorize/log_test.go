package authorize

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func Test_populateLogEvent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ctx = requestid.WithValue(ctx, "REQUEST-ID")

	req := &evaluator.Request{
		HTTP: evaluator.RequestHTTP{
			Method:   "GET",
			Host:     "HOST",
			RawPath:  "/some/path",
			RawQuery: "a=b",
			Headers:  map[string]string{"X-Request-Id": "CHECK-REQUEST-ID"},
			IP:       "127.0.0.1",
		},
		MCP: evaluator.RequestMCP{
			Method: "tools/call",
			ToolCall: &evaluator.RequestMCPToolCall{
				Name:      "list_tables",
				Arguments: map[string]interface{}{"database": "test", "schema": "public"},
			},
		},
		EnvoyRouteChecksum: 1234,
		EnvoyRouteID:       "ROUTE-ID",
		Policy: &config.Policy{
			ID: "POLICY-ID",
		},
	}
	s := &session.Session{
		Id: "SESSION-ID",
		IdToken: &session.IDToken{
			Raw: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2OTAzMTU4NjIsImV4cCI6MTcyMTg1MTg2MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.AAojgaG0fjMFwMCAC6YALHHMFIZEedFSP_vMGhiHhso",
		},
		UserId: "USER-ID",
	}
	sa := &user.ServiceAccount{
		Id:     "SERVICE-ACCOUNT-ID",
		UserId: "SERVICE-ACCOUNT-USER-ID",
	}
	u := &user.User{
		Id:    "USER-ID",
		Email: "EMAIL",
	}
	impersonateDetails := &impersonateDetails{
		email:     "IMPERSONATE-EMAIL",
		sessionID: "IMPERSONATE-SESSION-ID",
		userID:    "IMPERSONATE-USER-ID",
	}
	res := &evaluator.Result{
		AdditionalLogFields: map[log.AuthorizeLogField]any{
			log.AuthorizeLogFieldRemovedGroupsCount: 42,
		},
	}

	for _, tc := range []struct {
		field  log.AuthorizeLogField
		s      sessionOrServiceAccount
		expect string
	}{
		{log.AuthorizeLogFieldCheckRequestID, s, `{"check-request-id":"CHECK-REQUEST-ID"}`},
		{log.AuthorizeLogFieldEmail, s, `{"email":"EMAIL"}`},
		{log.AuthorizeLogFieldEnvoyRouteChecksum, s, `{"envoy-route-checksum":1234}`},
		{log.AuthorizeLogFieldEnvoyRouteID, s, `{"envoy-route-id":"ROUTE-ID"}`},
		{log.AuthorizeLogFieldHost, s, `{"host":"HOST"}`},
		{log.AuthorizeLogFieldIDToken, s, `{"id-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2OTAzMTU4NjIsImV4cCI6MTcyMTg1MTg2MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.AAojgaG0fjMFwMCAC6YALHHMFIZEedFSP_vMGhiHhso"}`},
		{log.AuthorizeLogFieldIDTokenClaims, s, `{"id-token-claims":{"Email":"jrocket@example.com","GivenName":"Johnny","Role":["Manager","Project Administrator"],"Surname":"Rocket","aud":"www.example.com","exp":1721851862,"iat":1690315862,"iss":"Online JWT Builder","sub":"jrocket@example.com"}}`},
		{log.AuthorizeLogFieldImpersonateEmail, s, `{"impersonate-email":"IMPERSONATE-EMAIL"}`},
		{log.AuthorizeLogFieldImpersonateSessionID, s, `{"impersonate-session-id":"IMPERSONATE-SESSION-ID"}`},
		{log.AuthorizeLogFieldImpersonateUserID, s, `{"impersonate-user-id":"IMPERSONATE-USER-ID"}`},
		{log.AuthorizeLogFieldIP, s, `{"ip":"127.0.0.1"}`},
		{log.AuthorizeLogFieldMCPMethod, s, `{"mcp-method":"tools/call"}`},
		{log.AuthorizeLogFieldMCPTool, s, `{"mcp-tool":"list_tables"}`},
		{log.AuthorizeLogFieldMCPToolParameters, s, `{"mcp-tool-parameters":{"database":"test","schema":"public"}}`},
		{log.AuthorizeLogFieldMethod, s, `{"method":"GET"}`},
		{log.AuthorizeLogFieldPath, s, `{"path":"/some/path"}`},
		{log.AuthorizeLogFieldQuery, s, `{"query":"a=b"}`},
		{log.AuthorizeLogFieldRemovedGroupsCount, s, `{"removed-groups-count":42}`},
		{log.AuthorizeLogFieldRequestID, s, `{"request-id":"REQUEST-ID"}`},
		{log.AuthorizeLogFieldRouteChecksum, s, `{"route-checksum":7416256365460802121}`},
		{log.AuthorizeLogFieldRouteID, s, `{"route-id":"POLICY-ID"}`},
		{log.AuthorizeLogFieldServiceAccountID, sa, `{"service-account-id":"SERVICE-ACCOUNT-ID"}`},
		{log.AuthorizeLogFieldSessionID, s, `{"session-id":"SESSION-ID"}`},
		{log.AuthorizeLogFieldUser, s, `{"user":"USER-ID"}`},
		{log.AuthorizeLogFieldUser, sa, `{"user":"SERVICE-ACCOUNT-USER-ID"}`},
		{log.AuthorizeLogFieldUser, nil, `{"user":""}`},
	} {
		t.Run(string(tc.field), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := zerolog.New(&buf)
			evt := log.Log()
			evt = populateLogEvent(ctx, tc.field, evt, req, tc.s, u, impersonateDetails, res)
			evt.Send()

			assert.Equal(t, tc.expect, strings.TrimSpace(buf.String()))
		})
	}
}

// Test_MCP_LogFields tests that MCP-specific log fields are properly populated
func Test_MCP_LogFields(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ctx = requestid.WithValue(ctx, "MCP-REQUEST-ID")

	// Test with a tools/call request
	req := &evaluator.Request{
		MCP: evaluator.RequestMCP{
			Method: "tools/call",
			ToolCall: &evaluator.RequestMCPToolCall{
				Name: "database_query",
				Arguments: map[string]interface{}{
					"query":  "SELECT * FROM users",
					"limit":  100,
					"format": "json",
				},
			},
		},
	}

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	// Test MCP method field
	evt := logger.Log()
	evt = populateLogEvent(ctx, log.AuthorizeLogFieldMCPMethod, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-method":"tools/call"`)
	buf.Reset()

	// Test MCP tool field
	evt = logger.Log()
	evt = populateLogEvent(ctx, log.AuthorizeLogFieldMCPTool, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-tool":"database_query"`)
	buf.Reset()

	// Test MCP tool parameters field
	evt = logger.Log()
	evt = populateLogEvent(ctx, log.AuthorizeLogFieldMCPToolParameters, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-tool-parameters":`)
	assert.Contains(t, buf.String(), `"query":"SELECT * FROM users"`)
	assert.Contains(t, buf.String(), `"limit":100`)
	assert.Contains(t, buf.String(), `"format":"json"`)
	buf.Reset()

	// Test with a non-tools/call request (no tool or parameters)
	req.MCP = evaluator.RequestMCP{
		Method: "tools/list",
	}

	evt = logger.Log()
	evt = populateLogEvent(ctx, log.AuthorizeLogFieldMCPMethod, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-method":"tools/list"`)
	buf.Reset()

	evt = logger.Log()
	evt = populateLogEvent(ctx, log.AuthorizeLogFieldMCPTool, evt, req, nil, nil, nil, nil)
	evt.Send()
	// Should not contain the field when ToolCall is nil
	assert.NotContains(t, buf.String(), `"mcp-tool"`)
	buf.Reset()

	// Test with empty MCP data
	req.MCP = evaluator.RequestMCP{}

	evt = logger.Log()
	evt = populateLogEvent(ctx, log.AuthorizeLogFieldMCPToolParameters, evt, req, nil, nil, nil, nil)
	evt.Send()
	// Should not contain the field when parameters are nil
	assert.NotContains(t, buf.String(), `"mcp-tool-parameters"`)
}
