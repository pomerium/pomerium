package authorize

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
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
	a := &Authorize{currentConfig: atomicutil.NewValue(&config.Config{
		Options: &config.Options{
			Policies: []config.Policy{{
				From: "https://example.com",
				SubPolicies: []config.SubPolicy{{
					Rego: []string{"allow = true"},
				}},
			}},
		},
	}), state: atomicutil.NewValue(new(authorizeState))}

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
		false, // mcp disabled
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
			IP: "",
		},
	}
	assert.Equal(t, expect, actual)
}

func Test_getEvaluatorRequestWithPortInHostHeader(t *testing.T) {
	a := &Authorize{currentConfig: atomicutil.NewValue(&config.Config{
		Options: &config.Options{
			Policies: []config.Policy{{
				From: "https://example.com",
				SubPolicies: []config.SubPolicy{{
					Rego: []string{"allow = true"},
				}},
			}},
		},
	}), state: atomicutil.NewValue(new(authorizeState))}

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
		}, false) // mcp disabled
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
		},
	}
	assert.Equal(t, expect, actual)
}

func Test_MCP_TraceAttributes(t *testing.T) {
	t.Parallel()

	// Test MCP request parsing
	mcpBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"database_query","arguments":{"query":"SELECT * FROM users","limit":10}}}`

	req := &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Body: mcpBody,
				},
			},
		},
	}

	mcpReq, ok := evaluator.RequestMCPFromCheckRequest(req)
	require.True(t, ok, "should successfully parse MCP request")

	assert.Equal(t, "tools/call", mcpReq.Method)
	require.NotNil(t, mcpReq.ToolCall)
	assert.Equal(t, "database_query", mcpReq.ToolCall.Name)
	assert.NotNil(t, mcpReq.ToolCall.Arguments)
	assert.Equal(t, "SELECT * FROM users", mcpReq.ToolCall.Arguments["query"])
	assert.Equal(t, float64(10), mcpReq.ToolCall.Arguments["limit"])

	// Test non-tools/call method
	mcpBodyList := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req.Attributes.Request.Http.Body = mcpBodyList

	mcpReq, ok = evaluator.RequestMCPFromCheckRequest(req)
	require.True(t, ok, "should successfully parse MCP list request")

	assert.Equal(t, "tools/list", mcpReq.Method)
	assert.Nil(t, mcpReq.ToolCall)

	// Test invalid JSON
	req.Attributes.Request.Http.Body = `invalid json`
	mcpReq, ok = evaluator.RequestMCPFromCheckRequest(req)
	assert.False(t, ok, "should fail to parse invalid JSON")

	// Test empty body
	req.Attributes.Request.Http.Body = ""
	mcpReq, ok = evaluator.RequestMCPFromCheckRequest(req)
	assert.False(t, ok, "should fail to parse empty body")
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
