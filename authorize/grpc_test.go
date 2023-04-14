package authorize

import (
	"context"
	"net/url"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
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
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: atomicutil.NewValue(new(authorizeState))}
	a.currentOptions.Store(&config.Options{
		Policies: []config.Policy{{
			From: "https://example.com",
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	})

	actual, err := a.getEvaluatorRequestFromCheckRequest(
		&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Source: &envoy_service_auth_v3.AttributeContext_Peer{
					Certificate: url.QueryEscape(certPEM),
				},
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Id:     "id-1234",
						Method: "GET",
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
			},
		},
		&sessions.State{
			ID: "SESSION_ID",
		},
	)
	require.NoError(t, err)
	expect := &evaluator.Request{
		Policy: &a.currentOptions.Load().Policies[0],
		Session: evaluator.RequestSession{
			ID: "SESSION_ID",
		},
		HTTP: evaluator.NewRequestHTTP(
			"GET",
			mustParseURL("http://example.com/some/path?qs=1"),
			map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			certPEM,
			"",
		),
	}
	assert.Equal(t, expect, actual)
}

func Test_getEvaluatorRequestWithPortInHostHeader(t *testing.T) {
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: atomicutil.NewValue(new(authorizeState))}
	a.currentOptions.Store(&config.Options{
		Policies: []config.Policy{{
			From: "https://example.com",
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	})

	actual, err := a.getEvaluatorRequestFromCheckRequest(&envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Source: &envoy_service_auth_v3.AttributeContext_Peer{
				Certificate: url.QueryEscape(certPEM),
			},
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Id:     "id-1234",
					Method: "GET",
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
	}, nil)
	require.NoError(t, err)
	expect := &evaluator.Request{
		Policy:  &a.currentOptions.Load().Policies[0],
		Session: evaluator.RequestSession{},
		HTTP: evaluator.NewRequestHTTP(
			"GET",
			mustParseURL("http://example.com/some/path?qs=1"),
			map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			certPEM,
			"",
		),
	}
	assert.Equal(t, expect, actual)
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

func mustParseURL(rawURL string) url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return *u
}
