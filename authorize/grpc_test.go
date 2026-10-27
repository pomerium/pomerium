package authorize

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const certPEM = `
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

func Test_getEvaluatorRequest(t *testing.T) {
	t.Parallel()

	a := &Authorize{}
	a.currentConfig.Store(config.New(&config.Options{
		Policies: []config.Policy{{
			From: "https://example.com",
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	}))
	a.state.Store(new(authorizeState))

	actual, err := a.getEvaluatorRequestFromCheckRequest(t.Context(),
		&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Id:     "id-1234",
						Method: http.MethodGet,
						Headers: map[string]string{
							"accept":            "text/html",
							"x-forwarded-proto": "https",
						},
						Path:   "/some/path?qs=1",
						Host:   "example.com",
						Scheme: "http",
						Body:   "BODY",
					},
				},
				MetadataContext: &envoy_config_core_v3.Metadata{
					FilterMetadata: map[string]*structpb.Struct{
						"com.pomerium.client-certificate-info": {
							Fields: map[string]*structpb.Value{
								"presented": structpb.NewBoolValue(true),
								"chain":     structpb.NewStringValue(url.QueryEscape(certPEM)),
							},
						},
					},
				},
			},
		},
	)
	require.NoError(t, err)
	expect := &evaluator.Request{
		Policy: &a.currentConfig.Load().Options.Policies[0],
		HTTP: evaluator.RequestHTTP{
			Method:   http.MethodGet,
			Host:     "example.com",
			Hostname: "example.com",
			Path:     "/some/path",
			RawPath:  "/some/path",
			RawQuery: "qs=1",
			URL:      "http://example.com/some/path?qs=1",
			Headers: map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			ClientCertificate: evaluator.ClientCertificateInfo{
				Presented:     true,
				Leaf:          certPEM[1:] + "\n",
				Intermediates: "",
			},
			IP:   "",
			Body: "BODY",
		},
	}
	assert.Equal(t, expect, actual)
}

func Test_getEvaluatorRequestWithPortInHostHeader(t *testing.T) {
	t.Parallel()

	a := &Authorize{}
	a.currentConfig.Store(config.New(&config.Options{
		Policies: []config.Policy{{
			From: "https://example.com",
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	}))
	a.state.Store(new(authorizeState))

	actual, err := a.getEvaluatorRequestFromCheckRequest(t.Context(),
		&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Id:     "id-1234",
						Method: http.MethodGet,
						Headers: map[string]string{
							"accept":            "text/html",
							"x-forwarded-proto": "https",
						},
						Path:   "/some/path?qs=1",
						Host:   "example.com:80",
						Scheme: "http",
						Body:   "BODY",
					},
				},
			},
		})
	require.NoError(t, err)
	expect := &evaluator.Request{
		Policy:  &a.currentConfig.Load().Options.Policies[0],
		Session: evaluator.RequestSession{},
		HTTP: evaluator.RequestHTTP{
			Method:   http.MethodGet,
			Host:     "example.com:80",
			Hostname: "example.com",
			Path:     "/some/path",
			RawPath:  "/some/path",
			RawQuery: "qs=1",
			URL:      "http://example.com/some/path?qs=1",
			Headers: map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			ClientCertificate: evaluator.ClientCertificateInfo{},
			IP:                "",
			Body:              "BODY",
		},
	}
	assert.Equal(t, expect, actual)
}

func Test_getEvaluatorRequestMCPBody(t *testing.T) {
	t.Parallel()

	maxRequestBytes := uint32(128)
	a := &Authorize{}
	a.currentConfig.Store(config.New(&config.Options{
		Policies: []config.Policy{{
			ID:   "mcp",
			From: "https://mcp.example.com",
			MCP: &config.MCP{
				Server: &config.MCPServer{MaxRequestBytes: &maxRequestBytes},
			},
		}},
	}))
	a.state.Store(new(authorizeState))

	getEvaluatorRequest := func(body string) error {
		_, err := a.getEvaluatorRequestFromCheckRequest(t.Context(),
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					ContextExtensions: envoyconfig.MakeExtAuthzContextExtensions(false, "mcp", 0),
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: http.MethodPost,
							Headers: map[string]string{
								"content-type":         "application/json",
								"mcp-protocol-version": "2025-11-25",
							},
							Host: "mcp.example.com",
							Body: body,
						},
					},
				},
			},
		)
		return err
	}

	// toolsList returns a tools/list request padded with leading whitespace to
	// exactly size bytes.
	toolsList := func(size int) string {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		return strings.Repeat(" ", size-len(body)) + body
	}

	assert.NoError(t, getEvaluatorRequest(toolsList(int(maxRequestBytes))),
		"a body at max_request_bytes should be accepted")
	assert.ErrorIs(t, getEvaluatorRequest(toolsList(int(maxRequestBytes)+1)), errMCPRequestBodyTooLarge,
		"a body past max_request_bytes should be rejected")
	assert.ErrorIs(t, getEvaluatorRequest(`[`+toolsList(int(maxRequestBytes)-2)+`]`), errMCPInvalidRequest,
		"a body that is not a single JSON-RPC message should be rejected")
}

// TestCheckRejectsMCPRequest verifies that an MCP request authorization cannot
// be evaluated against is rejected with a JSON error an MCP client can read,
// with the CORS headers a browser-based client needs to read it, and a generic
// reason, since the client has not been authenticated, unless the route shows
// error details; and that the rejection is logged with its cause like any other
// authorize check.
func TestCheckRejectsMCPRequest(t *testing.T) {
	t.Parallel()

	maxRequestBytes := uint32(128)
	for _, tc := range []struct {
		name             string
		showErrorDetails bool
		headers          map[string]string
		body             string
		wantStatus       int
		wantReason       string
		wantLogError     string
	}{
		{
			name:         "invalid",
			headers:      map[string]string{"content-type": "text/<html>"},
			body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			wantStatus:   http.StatusBadRequest,
			wantReason:   http.StatusText(http.StatusBadRequest),
			wantLogError: `failed to parse content-type "text/<html>"`,
		},
		{
			name:             "invalid with error details",
			showErrorDetails: true,
			headers:          map[string]string{"content-type": "text/<html>"},
			body:             `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			wantStatus:       http.StatusBadRequest,
			wantReason:       `invalid MCP request: failed to parse content-type "text/<html>": mime: expected token after slash`,
			wantLogError:     `failed to parse content-type "text/<html>"`,
		},
		{
			name:         "too large",
			body:         strings.Repeat(" ", int(maxRequestBytes)+1),
			wantStatus:   http.StatusRequestEntityTooLarge,
			wantReason:   http.StatusText(http.StatusRequestEntityTooLarge),
			wantLogError: errMCPRequestBodyTooLarge.Error(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := config.Policy{
				From:             "https://mcp.example.com",
				To:               mustParseWeightedURLs(t, "https://upstream.example.com"),
				ShowErrorDetails: tc.showErrorDetails,
				MCP: &config.MCP{
					Server: &config.MCPServer{MaxRequestBytes: &maxRequestBytes},
				},
			}
			routeID, err := policy.RouteID()
			require.NoError(t, err)
			opts := config.NewDefaultOptions()
			opts.Policies = []config.Policy{policy}
			a, err := New(t.Context(), config.New(opts))
			require.NoError(t, err)

			var logs bytes.Buffer
			ctx := zerolog.New(&logs).Level(zerolog.InfoLevel).WithContext(t.Context())

			headers := map[string]string{
				"accept":               "application/json, text/event-stream",
				"content-type":         "application/json",
				"mcp-protocol-version": "2025-11-25",
				"x-request-id":         "REQUEST-ID",
			}
			maps.Copy(headers, tc.headers)
			res, err := a.Check(ctx, &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					ContextExtensions: envoyconfig.MakeExtAuthzContextExtensions(false, routeID, 0),
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method:  http.MethodPost,
							Scheme:  "https",
							Host:    "mcp.example.com",
							Path:    "/mcp",
							Headers: headers,
							Body:    tc.body,
						},
					},
				},
			})
			require.NoError(t, err)

			denied := res.GetDeniedResponse()
			require.NotNil(t, denied, "request should be denied")
			assert.EqualValues(t, tc.wantStatus, denied.GetStatus().GetCode())

			gotHeaders := make(http.Header)
			for _, h := range denied.GetHeaders() {
				gotHeaders.Add(h.GetHeader().GetKey(), h.GetHeader().GetValue())
			}
			assert.Equal(t, "application/json", gotHeaders.Get("Content-Type"))
			wantCORSHeaders := make(http.Header)
			mcp.SetCORSHeaders(wantCORSHeaders)
			for k, v := range wantCORSHeaders {
				assert.Equal(t, v, gotHeaders.Values(k), "CORS header %s", k)
			}

			var body map[string]any
			require.NoError(t, json.Unmarshal([]byte(denied.GetBody()), &body), denied.GetBody())
			assert.Equal(t, map[string]any{
				"error":      tc.wantReason,
				"request_id": "REQUEST-ID",
			}, body, "response body")

			var entry map[string]any
			for line := range strings.Lines(logs.String()) {
				var e map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &e))
				if e["message"] == "authorize check" {
					entry = e
				}
			}
			require.NotNil(t, entry, "rejection should be logged as an authorize check: %s", logs.String())
			assert.Equal(t, "info", entry["level"])
			assert.Equal(t, routeID, entry["envoy-route-id"])
			assert.Contains(t, entry["error"], tc.wantLogError)
		})
	}
}

func Test_MCP_TraceAttributes(t *testing.T) {
	t.Parallel()

	mcpBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"database_query","arguments":{"query":"SELECT * FROM users","limit":10}}}`

	req := &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Method: http.MethodPost,
					Headers: map[string]string{
						"content-type":         "application/json",
						"mcp-protocol-version": "2025-11-25",
					},
					Body: mcpBody,
				},
			},
		},
	}

	mcpReq, err := evaluator.RequestMCPFromCheckRequest(req)
	require.NoError(t, err, "should successfully parse MCP request")

	assert.Equal(t, "tools/call", mcpReq.Method)
	require.NotNil(t, mcpReq.ToolCall)
	assert.Equal(t, "database_query", mcpReq.ToolCall.Name)
	assert.NotNil(t, mcpReq.ToolCall.Arguments)
	assert.Equal(t, "SELECT * FROM users", mcpReq.ToolCall.Arguments["query"])
	assert.Equal(t, float64(10), mcpReq.ToolCall.Arguments["limit"])

	// Test non-tools/call method
	mcpBodyList := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req.Attributes.Request.Http.Body = mcpBodyList

	mcpReq, err = evaluator.RequestMCPFromCheckRequest(req)
	require.NoError(t, err, "should successfully parse MCP list request")

	assert.Equal(t, "tools/list", mcpReq.Method)
	assert.Nil(t, mcpReq.ToolCall)

	// Test invalid JSON
	req.Attributes.Request.Http.Body = `invalid json`
	mcpReq, err = evaluator.RequestMCPFromCheckRequest(req)
	assert.Error(t, err, "should fail to parse invalid JSON")

	// Test empty body
	req.Attributes.Request.Http.Body = ""
	mcpReq, err = evaluator.RequestMCPFromCheckRequest(req)
	assert.Error(t, err, "should fail to parse empty body")
}

type mockDataBrokerServiceClient struct {
	databroker.DataBrokerServiceClient

	get func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error)
	put func(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error)
}

func (m mockDataBrokerServiceClient) Get(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
	return m.get(ctx, in, opts...)
}

func (m mockDataBrokerServiceClient) Put(ctx context.Context, in *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error) {
	return m.put(ctx, in, opts...)
}

// Patch emulates the patch operation using Get and Put. (This is not atomic.)
func (m mockDataBrokerServiceClient) Patch(ctx context.Context, in *databroker.PatchRequest, opts ...grpc.CallOption) (*databroker.PatchResponse, error) {
	var records []*databroker.Record
	for _, record := range in.GetRecords() {
		getResponse, err := m.Get(ctx, &databroker.GetRequest{
			Type: record.GetType(),
			Id:   record.GetId(),
		}, opts...)
		if storage.IsNotFound(err) {
			continue
		} else if err != nil {
			return nil, err
		}

		existing := getResponse.GetRecord()
		if err := storage.PatchRecord(existing, record, in.GetFieldMask()); err != nil {
			return nil, status.Error(codes.Unknown, err.Error())
		}

		records = append(records, record)
	}
	putResponse, err := m.Put(ctx, &databroker.PutRequest{Records: records}, opts...)
	if err != nil {
		return nil, err
	}
	return &databroker.PatchResponse{
		ServerVersion: putResponse.GetServerVersion(),
		Records:       putResponse.GetRecords(),
	}, nil
}
