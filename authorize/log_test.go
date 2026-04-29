package authorize

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/logfields"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func Test_logAuthorizeCheck(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	a, err := New(t.Context(), cfg)
	require.NoError(t, err)

	// Capture log output to a buffer.
	var b bytes.Buffer
	logger := zerolog.New(&b).Level(zerolog.DebugLevel)
	ctx := logger.WithContext(t.Context())

	// Set up a fake User databroker records.
	q := storage.NewStaticQuerier(
		&user.User{
			Id:    "USER-1",
			Email: "user@example.com",
		},
	)
	ctx = storage.WithQuerier(ctx, q)

	req := &evaluator.Request{
		Policy: &config.Policy{
			ID: "ROUTE-1",
		},
		HTTP: evaluator.RequestHTTP{
			Method:  "GET",
			Host:    "example.com:1234",
			RawPath: "/foo/bar",
			IP:      "1.2.3.4",
			Headers: map[string]string{
				"X-Request-Id": "CHECK-REQUEST-ID",
			},
		},
		Session: evaluator.RequestSession{
			ID: "SESS-1",
		},
		EnvoyRouteChecksum: 5678,
		EnvoyRouteID:       "ENVOY-ROUTE-1",
	}
	res := &evaluator.Result{
		Allow: evaluator.NewRuleResult(true, criteria.ReasonUserOK),
	}
	ctx = requestid.WithValue(ctx, "REQUEST-ID")

	a.logAuthorizeCheck(ctx, zerolog.InfoLevel, req, res, &session.Session{
		Id:     "SESS-1",
		UserId: "USER-1",
	})
	testutil.AssertJSONEqual(t, `{
		"level": "info",
		"service": "authorize",
		"request-id": "REQUEST-ID",
		"check-request-id": "CHECK-REQUEST-ID",
		"method": "GET",
		"path": "/foo/bar",
		"host": "example.com:1234",
		"ip": "1.2.3.4",
		"session-id": "SESS-1",
		"user": "USER-1",
		"email": "user@example.com",
		"envoy-route-checksum": 5678,
		"envoy-route-id": "ENVOY-ROUTE-1",
		"route-checksum": 15705525399004860503,
		"route-id": "ROUTE-1",
		"allow": true,
		"allow-why-true": ["user-ok"],
		"deny": false,
		"deny-why-false": [],
		"message": "authorize check"
	}`, b.String())
}

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
			Body:     `{"test":"request body"}`,
		},
		MCP: evaluator.RequestMCP{
			Method: "tools/call",
			ToolCall: &evaluator.RequestMCPToolCall{
				Name:      "list_tables",
				Arguments: map[string]any{"database": "test", "schema": "public"},
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
		AdditionalLogFields: map[logfields.AuthorizeLogField]any{
			logfields.AuthorizeLogFieldRemovedGroupsCount: 42,
		},
	}

	var unknownAuthLogfield logfields.AuthorizeLogField = "blah"

	for _, tc := range []struct {
		field  logfields.AuthorizeLogField
		s      sessionOrServiceAccount
		expect string
	}{
		{logfields.AuthorizeLogFieldBody, s, `{"body":"{\"test\":\"request body\"}"}`},
		{logfields.AuthorizeLogFieldCheckRequestID, s, `{"check-request-id":"CHECK-REQUEST-ID"}`},
		{logfields.AuthorizeLogFieldEmail, s, `{"email":"EMAIL"}`},
		{logfields.AuthorizeLogFieldEnvoyRouteChecksum, s, `{"envoy-route-checksum":1234}`},
		{logfields.AuthorizeLogFieldEnvoyRouteID, s, `{"envoy-route-id":"ROUTE-ID"}`},
		{logfields.AuthorizeLogFieldHost, s, `{"host":"HOST"}`},
		{logfields.AuthorizeLogFieldIDToken, s, `{"id-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2OTAzMTU4NjIsImV4cCI6MTcyMTg1MTg2MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.AAojgaG0fjMFwMCAC6YALHHMFIZEedFSP_vMGhiHhso"}`},
		{logfields.AuthorizeLogFieldIDTokenClaims, s, `{"id-token-claims":{"Email":"jrocket@example.com","GivenName":"Johnny","Role":["Manager","Project Administrator"],"Surname":"Rocket","aud":"www.example.com","exp":1721851862,"iat":1690315862,"iss":"Online JWT Builder","sub":"jrocket@example.com"}}`},
		{logfields.AuthorizeLogFieldImpersonateEmail, s, `{"impersonate-email":"IMPERSONATE-EMAIL"}`},
		{logfields.AuthorizeLogFieldImpersonateSessionID, s, `{"impersonate-session-id":"IMPERSONATE-SESSION-ID"}`},
		{logfields.AuthorizeLogFieldImpersonateUserID, s, `{"impersonate-user-id":"IMPERSONATE-USER-ID"}`},
		{logfields.AuthorizeLogFieldIP, s, `{"ip":"127.0.0.1"}`},
		{logfields.AuthorizeLogFieldMCPMethod, s, `{"mcp-method":"tools/call"}`},
		{logfields.AuthorizeLogFieldMCPTool, s, `{"mcp-tool":"list_tables"}`},
		{logfields.AuthorizeLogFieldMCPToolParameters, s, `{"mcp-tool-parameters":{"database":"test","schema":"public"}}`},
		{logfields.AuthorizeLogFieldMethod, s, `{"method":"GET"}`},
		{logfields.AuthorizeLogFieldPath, s, `{"path":"/some/path"}`},
		{logfields.AuthorizeLogFieldQuery, s, `{"query":"a=b"}`},
		{logfields.AuthorizeLogFieldRemovedGroupsCount, s, `{"removed-groups-count":42}`},
		{logfields.AuthorizeLogFieldRequestID, s, `{"request-id":"REQUEST-ID"}`},
		{logfields.AuthorizeLogFieldRouteChecksum, s, `{"route-checksum":9741033360086775695}`},
		{logfields.AuthorizeLogFieldRouteID, s, `{"route-id":"POLICY-ID"}`},
		{logfields.AuthorizeLogFieldServiceAccountID, sa, `{"service-account-id":"SERVICE-ACCOUNT-ID"}`},
		{logfields.AuthorizeLogFieldSessionID, s, `{"session-id":"SESSION-ID"}`},
		{logfields.AuthorizeLogFieldUser, s, `{"user":"USER-ID"}`},
		{logfields.AuthorizeLogFieldUser, sa, `{"user":"SERVICE-ACCOUNT-USER-ID"}`},
		{logfields.AuthorizeLogFieldUser, nil, `{"user":""}`},
		{unknownAuthLogfield, nil, "{}"},
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
				Arguments: map[string]any{
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
	evt = populateLogEvent(ctx, logfields.AuthorizeLogFieldMCPMethod, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-method":"tools/call"`)
	buf.Reset()

	// Test MCP tool field
	evt = logger.Log()
	evt = populateLogEvent(ctx, logfields.AuthorizeLogFieldMCPTool, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-tool":"database_query"`)
	buf.Reset()

	// Test MCP tool parameters field
	evt = logger.Log()
	evt = populateLogEvent(ctx, logfields.AuthorizeLogFieldMCPToolParameters, evt, req, nil, nil, nil, nil)
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
	evt = populateLogEvent(ctx, logfields.AuthorizeLogFieldMCPMethod, evt, req, nil, nil, nil, nil)
	evt.Send()
	assert.Contains(t, buf.String(), `"mcp-method":"tools/list"`)
	buf.Reset()

	evt = logger.Log()
	evt = populateLogEvent(ctx, logfields.AuthorizeLogFieldMCPTool, evt, req, nil, nil, nil, nil)
	evt.Send()
	// Should not contain the field when ToolCall is nil
	assert.NotContains(t, buf.String(), `"mcp-tool"`)
	buf.Reset()

	// Test with empty MCP data
	req.MCP = evaluator.RequestMCP{}

	evt = logger.Log()
	evt = populateLogEvent(ctx, logfields.AuthorizeLogFieldMCPToolParameters, evt, req, nil, nil, nil, nil)
	evt.Send()
	// Should not contain the field when parameters are nil
	assert.NotContains(t, buf.String(), `"mcp-tool-parameters"`)
}
