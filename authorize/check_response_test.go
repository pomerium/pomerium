package authorize

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func mustID(v any) jsonrpc.ID {
	id, err := jsonrpc.MakeID(v)
	if err != nil {
		panic(err)
	}
	return id
}

func TestAuthorize_handleResult(t *testing.T) {
	t.Parallel()

	opt := config.NewDefaultOptions()
	opt.DataBroker.ServiceURL = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="

	hpkePrivateKey, err := opt.GetHPKEPrivateKey()
	require.NoError(t, err)

	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opt.AuthenticateURLString = authnSrv.URL

	a, err := New(t.Context(), &config.Config{Options: opt})
	require.NoError(t, err)

	t.Run("user-unauthenticated", func(t *testing.T) {
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))

		res, err = a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Deny: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("device-unauthenticated", func(t *testing.T) {
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonDeviceUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))

		t.Run("webauthn path", func(t *testing.T) {
			res, err := a.handleResult(t.Context(),
				&envoy_service_auth_v3.CheckRequest{
					Attributes: &envoy_service_auth_v3.AttributeContext{
						Request: &envoy_service_auth_v3.AttributeContext_Request{
							Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
								Path: "/.pomerium/webauthn",
							},
						},
					},
				},
				&evaluator.Request{},
				&evaluator.Result{
					Allow: evaluator.NewRuleResult(true, criteria.ReasonPomeriumRoute),
					Deny:  evaluator.NewRuleResult(false, criteria.ReasonDeviceUnauthenticated),
				})
			assert.NoError(t, err)
			assert.NotNil(t, res.GetOkResponse())
		})
	})
	t.Run("invalid-client-certificate", func(t *testing.T) {
		// Even if the user is unauthenticated, if a client certificate was required and an invalid
		// certificate was provided, access should be denied (no login redirect).
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
				Deny:  evaluator.NewRuleResult(true, criteria.ReasonInvalidClientCertificate),
			})
		assert.NoError(t, err)
		assert.Equal(t, 495, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("client-certificate-required", func(t *testing.T) {
		// Likewise, if a client certificate was required and no certificate
		// was presented, access should be denied (no login redirect).
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
				Deny:  evaluator.NewRuleResult(true, criteria.ReasonClientCertificateRequired),
			})
		assert.NoError(t, err)
		assert.Equal(t, 495, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("mcp-route-user-unauthenticated, mcp flag is on", func(t *testing.T) {
		opt.RuntimeFlags[config.RuntimeFlagMCP] = true
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{
				Policy: &config.Policy{MCP: &config.MCP{Server: &config.MCPServer{}}},
			},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 401, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("mcp-route-user-unauthenticated, mcp flag is off", func(t *testing.T) {
		opt.RuntimeFlags[config.RuntimeFlagMCP] = false
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{
				Policy: &config.Policy{MCP: &config.MCP{Server: &config.MCPServer{}}},
			},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("mcp-route-unauthenticated, mcp flag is on", func(t *testing.T) {
		opt.RuntimeFlags[config.RuntimeFlagMCP] = true
		res, err := a.handleResult(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{
				HTTP:   evaluator.RequestHTTP{Host: "example.com"},
				Policy: &config.Policy{MCP: &config.MCP{Server: &config.MCPServer{}}},
			},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false),
			})
		assert.NoError(t, err)
		assert.Equal(t, 401, int(res.GetDeniedResponse().GetStatus().GetCode()))
		assertContainsHeaderValue(t,
			"Www-Authenticate",
			`Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			res.GetDeniedResponse().GetHeaders())
		assert.Contains(t, res.GetDeniedResponse().GetBody(),
			"This is an MCP route. It is not meant to be accessed directly in the browser.")
	})
	t.Run("mcp-route-denied", func(t *testing.T) {
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "test-request-id-123")

		res, err := a.handleResultDenied(ctx,
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Body: `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"forbidden_tool","arguments":{"query":"SELECT * FROM secret_data"}}}`,
						},
					},
				},
			},
			&evaluator.Request{
				Policy: &config.Policy{
					MCP: &config.MCP{Server: &config.MCPServer{}},
				},
				MCP: evaluator.RequestMCP{
					ID:     mustID(42.0),
					Method: "tools/call",
					ToolCall: &evaluator.RequestMCPToolCall{
						Name:      "forbidden_tool",
						Arguments: map[string]any{"query": "SELECT * FROM secret_data"},
					},
				},
			},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonMCPToolNoMatch),
			},
			criteria.Reasons{criteria.ReasonMCPToolNoMatch: {}},
		)
		assert.NoError(t, err)
		assert.NotNil(t, res)

		assert.NotNil(t, res.GetDeniedResponse())
		assert.Equal(t, int32(200), int32(res.GetDeniedResponse().GetStatus().GetCode())) // MCP uses 200 OK with JSON-RPC error

		body := res.GetDeniedResponse().GetBody()
		assert.Contains(t, body, `"jsonrpc":"2.0"`)
		assert.Contains(t, body, `"id":42`)
		assert.Contains(t, body, `"error"`)
		assert.Contains(t, body, `"code":-32602`) // Invalid params error code
		assert.Contains(t, body, "access denied")
		assert.Contains(t, body, "test-request-id-123")

		headers := res.GetDeniedResponse().GetHeaders()
		assert.Len(t, headers, 2)

		var contentTypeFound, cacheControlFound bool
		for _, header := range headers {
			switch header.GetHeader().GetKey() {
			case "Content-Type":
				assert.Equal(t, "application/json", header.GetHeader().GetValue())
				contentTypeFound = true
			case "Cache-Control":
				assert.Equal(t, "no-cache", header.GetHeader().GetValue())
				cacheControlFound = true
			}
		}
		assert.True(t, contentTypeFound, "Content-Type header should be set")
		assert.True(t, cacheControlFound, "Cache-Control header should be set")
	})
	t.Run("mcp-request-with-tool-call-denied", func(t *testing.T) {
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "integration-test-789")

		res, err := a.handleResult(ctx,
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Body: `{"jsonrpc":"2.0","id":789,"method":"tools/call","params":{"name":"admin_tool","arguments":{"action":"delete_all"}}}`,
						},
					},
				},
			},
			&evaluator.Request{
				Policy: &config.Policy{
					MCP: &config.MCP{Server: &config.MCPServer{}},
				},
				MCP: evaluator.RequestMCP{
					ID:     mustID(789.0),
					Method: "tools/call",
					ToolCall: &evaluator.RequestMCPToolCall{
						Name:      "admin_tool",
						Arguments: map[string]any{"action": "delete_all"},
					},
				},
			},
			&evaluator.Result{
				Deny: evaluator.NewRuleResult(true, criteria.ReasonMCPToolNoMatch),
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, res)

		deniedResp := res.GetDeniedResponse()
		assert.NotNil(t, deniedResp)
		assert.Equal(t, int32(200), int32(deniedResp.GetStatus().GetCode()))

		body := deniedResp.GetBody()
		assert.Contains(t, body, `"jsonrpc":"2.0"`)
		assert.Contains(t, body, `"id":789`)
		assert.Contains(t, body, `"error"`)
		assert.Contains(t, body, "integration-test-789")

		headers := deniedResp.GetHeaders()
		var foundContentType bool
		for _, header := range headers {
			if header.GetHeader().GetKey() == "Content-Type" {
				assert.Equal(t, "application/json", header.GetHeader().GetValue())
				foundContentType = true
				break
			}
		}
		assert.True(t, foundContentType, "Content-Type header should be application/json for MCP responses")
	})
}

func TestAuthorize_okResponse(t *testing.T) {
	t.Parallel()

	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
		JWTClaimsHeaders: config.NewJWTClaimHeaders("email"),
	}
	a := &Authorize{}
	a.currentConfig.Store(&config.Config{
		Options: opt,
	})
	a.state.Store(new(authorizeState))
	a.store = store.New()
	pe, err := newPolicyEvaluator(t.Context(), opt, a.store, nil)
	require.NoError(t, err)
	a.state.Load().evaluator = pe

	tests := []struct {
		name  string
		reply *evaluator.Result
		want  *envoy_service_auth_v3.CheckResponse
	}{
		{
			"ok reply",
			&evaluator.Result{Allow: evaluator.NewRuleResult(true)},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "OK"},
			},
		},
		{
			"ok reply with k8s svc",
			&evaluator.Result{Allow: evaluator.NewRuleResult(true)},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "OK"},
			},
		},
		{
			"ok reply with k8s svc impersonate",
			&evaluator.Result{Allow: evaluator.NewRuleResult(true)},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "OK"},
			},
		},
		{
			"ok reply with jwt claims header",
			&evaluator.Result{Allow: evaluator.NewRuleResult(true)},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "OK"},
			},
		},
		{
			"ok reply with headers to remove",
			&evaluator.Result{
				Allow:           evaluator.NewRuleResult(true),
				HeadersToRemove: []string{"x-header-to-remove"},
			},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "OK"},
				HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v3.OkHttpResponse{
						HeadersToRemove: []string{"x-header-to-remove"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := a.okResponse(tc.reply.Headers, tc.reply.HeadersToRemove)
			assert.Equal(t, tc.want.Status.Code, got.Status.Code)
			assert.Equal(t, tc.want.Status.Message, got.Status.Message)
			want, _ := protojson.Marshal(tc.want.GetOkResponse())
			testutil.AssertProtoJSONEqual(t, string(want), got.GetOkResponse())
		})
	}
}

func TestAuthorize_deniedResponse(t *testing.T) {
	t.Parallel()

	a := &Authorize{}
	a.currentConfig.Store(&config.Config{
		Options: &config.Options{
			Policies: []config.Policy{{
				From: "https://example.com",
				SubPolicies: []config.SubPolicy{{
					Rego: []string{"allow = true"},
				}},
			}},
		},
	})
	a.state.Store(new(authorizeState))

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "REQUESTID")

		res, err := a.deniedResponse(ctx, &envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"Accept": "application/json",
						},
					},
				},
			},
		}, http.StatusBadRequest, "ERROR", nil)
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"deniedResponse": {
				"body": "{\"error\":\"ERROR\",\"request_id\":\"REQUESTID\"}",
				"headers": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "Content-Type", "value": "application/json" }
					}
				],
				"status": {
					"code": "BadRequest"
				}
			},
			"status": {
				"code": 7,
				"message": "Access Denied"
			}
		}`, res)
	})

	t.Run("grpc", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "REQUESTID")

		res, err := a.deniedResponse(ctx, &envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"content-type": "application/grpc+json",
						},
					},
				},
			},
		}, http.StatusBadRequest, "ERROR", nil)
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"deniedResponse": {
				"headers": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "Content-Type", "value": "application/grpc+json" }
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "grpc-message", "value": "ERROR" }
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "grpc-status", "value": "13" }
					}
				],
				"status": {
					"code": "BadRequest"
				}
			},
			"status": {
				"code": 7,
				"message": "Access Denied"
			}
		}`, res)
	})

	t.Run("grpc-web", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "REQUESTID")

		res, err := a.deniedResponse(ctx, &envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"content-type": "application/grpc-web-text",
						},
					},
				},
			},
		}, http.StatusBadRequest, "ERROR", nil)
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"deniedResponse": {
				"headers": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "Content-Type", "value": "application/grpc-web+json" }
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "grpc-message", "value": "ERROR" }
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "grpc-status", "value": "13" }
					}
				],
				"status": {
					"code": "BadRequest"
				}
			},
			"status": {
				"code": 7,
				"message": "Access Denied"
			}
		}`, res)
	})

	t.Run("kubernetes", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "REQUESTID")

		for _, tc := range []struct {
			code   int32
			reason string

			expectedMessage    string
			expectedReason     string
			expectedStatusCode string
		}{
			{401, "Unauthorized", "Unauthorized", "Unauthorized", `"Unauthorized"`},
			{403, "Forbidden", "Forbidden", "Forbidden", `"Forbidden"`},
			{404, "Not Found", "Not Found", "NotFound", `"NotFound"`},
			{400, "Bad Request", "Bad Request", "", `"BadRequest"`},
			{450, "", "your device fails to meet the requirements necessary to access this page, please contact your administrator for assistance", "Unauthorized", `450`},
			{495, "", "a valid client certificate is required to access this page", "Unauthorized", `495`},
			{500, "Internal Server Error", "Internal Server Error", "", `"InternalServerError"`},
		} {
			res, err := a.deniedResponse(ctx, &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"Accept":     "application/json",
								"User-Agent": "kubectl/vX.Y.Z (linux/amd64) kubernetes/000000",
							},
						},
					},
				},
			}, tc.code, tc.reason, nil)
			assert.NoError(t, err)
			testutil.AssertProtoJSONEqual(t, fmt.Sprintf(`{
			"deniedResponse": {
				"body": "{\"apiVersion\":\"v1\",\"code\":%[1]d,\"kind\":\"Status\",\"message\":\"%[2]s\",\"reason\":\"%[3]s\",\"status\":\"Failure\"}",
				"headers": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "Content-Type", "value": "application/json" }
					}
				],
				"status": {
					"code": %[4]s
				}
			},
			"status": {
				"code": 7,
				"message": "Access Denied"
			}
		}`, tc.code, tc.expectedMessage, tc.expectedReason, tc.expectedStatusCode), res)
		}
	})

	t.Run("html", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "REQUESTID")

		res, err := a.deniedResponse(ctx, &envoy_service_auth_v3.CheckRequest{}, http.StatusBadRequest, "ERROR", nil)
		assert.NoError(t, err)
		assert.Contains(t, res.GetDeniedResponse().GetBody(), "<!DOCTYPE html>")
		res.HttpResponse.(*envoy_service_auth_v3.CheckResponse_DeniedResponse).DeniedResponse.Body = ""
		testutil.AssertProtoJSONEqual(t, `{
			"deniedResponse": {
				"headers": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "Content-Type", "value": "text/html; charset=UTF-8" }
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "X-Pomerium-Intercepted-Response", "value": "true" }
					}
				],
				"status": {
					"code": "BadRequest"
				}
			},
			"status": {
				"code": 7,
				"message": "Access Denied"
			}
		}`, res)
	})
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func TestRequireLogin(t *testing.T) {
	t.Parallel()

	opt := config.NewDefaultOptions()
	opt.DataBroker.ServiceURL = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="
	opt.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUJlMFRxbXJkSXBZWE03c3pSRERWYndXOS83RWJHVWhTdFFJalhsVHNXM1BvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFb0xaRDI2bEdYREhRQmhhZkdlbEVmRDdlNmYzaURjWVJPVjdUbFlIdHF1Y1BFL2hId2dmYQpNY3FBUEZsRmpueUpySXJhYTFlQ2xZRTJ6UktTQk5kNXBRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="

	hpkePrivateKey, err := opt.GetHPKEPrivateKey()
	require.NoError(t, err)

	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opt.AuthenticateURLString = authnSrv.URL

	a, err := New(t.Context(), &config.Config{Options: opt})
	require.NoError(t, err)

	t.Run("accept empty", func(t *testing.T) {
		res, err := a.requireLoginResponse(t.Context(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{})
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("accept html", func(t *testing.T) {
		res, err := a.requireLoginResponse(t.Context(),
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"accept": "*/*",
							},
						},
					},
				},
			},
			&evaluator.Request{})
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("accept json", func(t *testing.T) {
		res, err := a.requireLoginResponse(t.Context(),
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Headers: map[string]string{
								"accept": "application/json",
							},
						},
					},
				},
			},
			&evaluator.Request{})
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
}

func Test_deniedResponseForMCP(t *testing.T) {
	t.Parallel()

	t.Run("basic mcp denied response", func(t *testing.T) {
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "test-request-id-456")

		res := deniedResponseForMCP(ctx, mustID(123.0))

		assert.NotNil(t, res)
		assert.NotNil(t, res.GetDeniedResponse())
		assert.Equal(t, int32(200), int32(res.GetDeniedResponse().GetStatus().GetCode()))
		body := res.GetDeniedResponse().GetBody()

		var jsonRPCError struct {
			JSONrpc string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Data    struct {
					RequestID string `json:"request_id"`
				} `json:"data"`
			} `json:"error"`
		}

		err := json.Unmarshal([]byte(body), &jsonRPCError)
		require.NoError(t, err, "Response body should be valid JSON")

		assert.Equal(t, "2.0", jsonRPCError.JSONrpc)
		assert.Equal(t, 123, jsonRPCError.ID)
		assert.Equal(t, -32602, jsonRPCError.Error.Code) // Invalid params error
		assert.Contains(t, jsonRPCError.Error.Message, "access denied")
		assert.Contains(t, jsonRPCError.Error.Message, "test-request-id-456")
		assert.Equal(t, "test-request-id-456", jsonRPCError.Error.Data.RequestID)

		headers := res.GetDeniedResponse().GetHeaders()
		assert.Len(t, headers, 2)

		headerMap := make(map[string]string)
		for _, header := range headers {
			headerMap[header.GetHeader().GetKey()] = header.GetHeader().GetValue()
		}

		assert.Equal(t, "application/json", headerMap["Content-Type"])
		assert.Equal(t, "no-cache", headerMap["Cache-Control"])
	})

	t.Run("different request id", func(t *testing.T) {
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "different-request-id")

		res := deniedResponseForMCP(ctx, mustID(999.0))

		body := res.GetDeniedResponse().GetBody()
		assert.Contains(t, body, `"id":999`)
		assert.Contains(t, body, "different-request-id")
	})

	t.Run("zero id", func(t *testing.T) {
		ctx := t.Context()
		ctx = requestid.WithValue(ctx, "zero-id-test")

		res := deniedResponseForMCP(ctx, mustID(0.0))

		body := res.GetDeniedResponse().GetBody()
		assert.Contains(t, body, `"id":0`)
		assert.Contains(t, body, "zero-id-test")
	})
}

func assertContainsHeaderValue(t *testing.T, key, value string, headers []*envoy_config_core_v3.HeaderValueOption) {
	t.Helper()
	for _, h := range headers {
		if h.Header.Key == key {
			assert.Equal(t, value, h.Header.Value)
			return
		}
	}
	t.Errorf("header with key %q not found in headers", key)
}
