package authorize

import (
	"context"
	"net/url"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
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
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0})
	a.state.Load().encoder = encoder
	a.currentOptions.Store(&config.Options{
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
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
		HTTP: evaluator.RequestHTTP{
			Method: "GET",
			URL:    "http://example.com/some/path?qs=1",
			Headers: map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			ClientCertificate: certPEM,
		},
	}
	assert.Equal(t, expect, actual)
}

func Test_handleForwardAuth(t *testing.T) {
	tests := []struct {
		name           string
		checkReq       *envoy_service_auth_v3.CheckRequest
		forwardAuthURL string
		want           bool
	}{
		{
			name: "enabled",
			checkReq: &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=" + url.QueryEscape("https://example.com/some/path?qs=1"),
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			want:           true,
		},
		{
			name:           "disabled",
			checkReq:       nil,
			forwardAuthURL: "",
			want:           false,
		},
		{
			name: "honor x-forwarded-uri set",
			checkReq: &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/",
							Host:   "forward-auth.example.com",
							Scheme: "https",
							Headers: map[string]string{
								httputil.HeaderForwardedURI:   "/foo/bar",
								httputil.HeaderForwardedProto: "https",
								httputil.HeaderForwardedHost:  "example.com",
							},
						},
					},
				},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			want:           true,
		},
		{
			name: "request with invalid forward auth url",
			checkReq: &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=" + url.QueryEscape("https://example.com?q=foo"),
							Host:   "fake-forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			want:           false,
		},
		{
			name: "request with invalid path",
			checkReq: &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/foo?uri=" + url.QueryEscape("https://example.com?q=foo"),
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			want:           true,
		},
		{
			name: "request with empty uri",
			checkReq: &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=",
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			want:           true,
		},
		{
			name: "request with invalid uri",
			checkReq: &envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri= http://example.com/foo",
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			want:           true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
			a.currentOptions.Store(&config.Options{ForwardAuthURLString: tc.forwardAuthURL})

			got := a.isForwardAuth(tc.checkReq)

			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("Authorize.Check() = %s", diff)
			}
		})
	}
}

func Test_getEvaluatorRequestWithPortInHostHeader(t *testing.T) {
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0})
	a.state.Load().encoder = encoder
	a.currentOptions.Store(&config.Options{
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
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
		HTTP: evaluator.RequestHTTP{
			Method: "GET",
			URL:    "http://example.com/some/path?qs=1",
			Headers: map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			ClientCertificate: certPEM,
		},
	}
	assert.Equal(t, expect, actual)
}

type mockDataBrokerServiceClient struct {
	databroker.DataBrokerServiceClient

	get func(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error)
}

func (m mockDataBrokerServiceClient) Get(ctx context.Context, in *databroker.GetRequest, opts ...grpc.CallOption) (*databroker.GetResponse, error) {
	return m.get(ctx, in, opts...)
}

func TestAuthorize_Check(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURLString = "https://authenticate.example.com"
	opt.DataBrokerURLString = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="
	a, err := New(&config.Config{Options: opt})
	if err != nil {
		t.Fatal(err)
	}
	a.currentOptions.Store(&config.Options{ForwardAuthURLString: "https://forward-auth.example.com"})

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(envoy_service_auth_v3.CheckResponse{}),
		cmpopts.IgnoreUnexported(status.Status{}),
		cmpopts.IgnoreTypes(envoy_service_auth_v3.DeniedHttpResponse{}),
	}
	tests := []struct {
		name    string
		in      *envoy_service_auth_v3.CheckRequest
		want    *envoy_service_auth_v3.CheckResponse
		wantErr bool
	}{
		{
			"basic deny",
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
								"accept":            "application/json",
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
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 7, Message: "Access Denied"},
				HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
					DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{},
				},
			},
			false,
		},
		{
			"basic forward-auth deny",
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Source: &envoy_service_auth_v3.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=" + url.QueryEscape("https://example.com/some/path?qs=1"),
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 7, Message: "Access Denied"},
				HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
					DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.Check(context.TODO(), tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize.Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("NewStore() = %s", diff)
			}
		})
	}
}
