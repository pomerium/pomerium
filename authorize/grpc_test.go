package authorize

import (
	"net/url"
	"testing"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding/jws"
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
	a := new(Authorize)
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0}, "")
	a.currentEncoder.Store(encoder)

	actual := a.getEvaluatorRequestFromCheckRequest(&envoy_service_auth_v2.CheckRequest{
		Attributes: &envoy_service_auth_v2.AttributeContext{
			Source: &envoy_service_auth_v2.AttributeContext_Peer{
				Certificate: url.QueryEscape(certPEM),
			},
			Request: &envoy_service_auth_v2.AttributeContext_Request{
				Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
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
	}, nil)
	expect := &evaluator.Request{
		Session: evaluator.RequestSession{},
		HTTP: evaluator.RequestHTTP{
			Method: "GET",
			URL:    "https://example.com/some/path?qs=1",
			Path:   "/some/path",
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
		checkReq       *envoy_service_auth_v2.CheckRequest
		attrCtxHTTPReq *envoy_service_auth_v2.AttributeContext_HttpRequest
		forwardAuthURL string
		isForwardAuth  bool
	}{
		{
			name: "enabled",
			checkReq: &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Source: &envoy_service_auth_v2.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=" + url.QueryEscape("https://example.com/some/path?qs=1"),
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			attrCtxHTTPReq: &envoy_service_auth_v2.AttributeContext_HttpRequest{
				Method: "GET",
				Path:   "/some/path?qs=1",
				Host:   "example.com",
				Scheme: "https",
			},
			forwardAuthURL: "https://forward-auth.example.com",
			isForwardAuth:  true,
		},
		{
			name:           "disabled",
			checkReq:       nil,
			attrCtxHTTPReq: nil,
			forwardAuthURL: "",
			isForwardAuth:  false,
		},
		{
			name: "honor x-forwarded-uri set",
			checkReq: &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Source: &envoy_service_auth_v2.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Method:  "GET",
							Path:    "/verify?uri=" + url.QueryEscape("https://example.com?q=foo"),
							Host:    "forward-auth.example.com",
							Scheme:  "https",
							Headers: map[string]string{"X-Forwarded-Uri": "/foo/bar"},
						},
					},
				},
			},
			attrCtxHTTPReq: &envoy_service_auth_v2.AttributeContext_HttpRequest{
				Method:  "GET",
				Path:    "/foo/bar?q=foo",
				Host:    "example.com",
				Scheme:  "https",
				Headers: map[string]string{"X-Forwarded-Uri": "/foo/bar"},
			},
			forwardAuthURL: "https://forward-auth.example.com",
			isForwardAuth:  true,
		},
		{
			name: "request with invalid forward auth url",
			checkReq: &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Source: &envoy_service_auth_v2.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=" + url.QueryEscape("https://example.com?q=foo"),
							Host:   "fake-forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			attrCtxHTTPReq: nil,
			forwardAuthURL: "https://forward-auth.example.com",
			isForwardAuth:  false,
		},
		{
			name: "request with invalid path",
			checkReq: &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Source: &envoy_service_auth_v2.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/foo?uri=" + url.QueryEscape("https://example.com?q=foo"),
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			attrCtxHTTPReq: nil,
			forwardAuthURL: "https://forward-auth.example.com",
			isForwardAuth:  false,
		},
		{
			name: "request with empty uri",
			checkReq: &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Source: &envoy_service_auth_v2.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri=",
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			attrCtxHTTPReq: nil,
			forwardAuthURL: "https://forward-auth.example.com",
			isForwardAuth:  false,
		},
		{
			name: "request with invalid uri",
			checkReq: &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Source: &envoy_service_auth_v2.AttributeContext_Peer{
						Certificate: url.QueryEscape(certPEM),
					},
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Method: "GET",
							Path:   "/verify?uri= http://example.com/foo",
							Host:   "forward-auth.example.com",
							Scheme: "https",
						},
					},
				},
			},
			attrCtxHTTPReq: nil,
			forwardAuthURL: "https://forward-auth.example.com",
			isForwardAuth:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := new(Authorize)
			fau := new(url.URL)
			if tc.forwardAuthURL != "" {
				fau = mustParseURL(tc.forwardAuthURL)
			}
			a.currentOptions.Store(config.Options{ForwardAuthURL: fau})
			assert.Equal(t, tc.isForwardAuth, a.handleForwardAuth(tc.checkReq))
			if tc.attrCtxHTTPReq != nil {
				assert.Equal(t, tc.attrCtxHTTPReq, tc.checkReq.Attributes.Request.Http)
			}
		})
	}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
