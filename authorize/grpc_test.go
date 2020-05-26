package authorize

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2/jwt"
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
	actual := getEvaluatorRequestFromCheckRequest(&envoy_service_auth_v2.CheckRequest{
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
	}, []byte("HELLO WORLD"))
	expect := &evaluator.Request{
		User:   "HELLO WORLD",
		Method: "GET",
		URL:    "https://example.com/some/path?qs=1",
		Header: map[string][]string{
			"Accept":            {"text/html"},
			"X-Forwarded-Proto": {"https"},
		},
		Host:              "example.com",
		RequestURI:        "https://example.com/some/path?qs=1",
		ClientCertificate: certPEM,
	}
	assert.Equal(t, expect, actual)
}

func Test_handleForwardAuth(t *testing.T) {
	checkReq := &envoy_service_auth_v2.CheckRequest{
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
	}

	t.Run("enabled", func(t *testing.T) {
		a := new(Authorize)
		a.currentOptions.Store(config.Options{
			ForwardAuthURL: mustParseURL("https://forward-auth.example.com"),
		})
		isForwardAuth := a.handleForwardAuth(checkReq)
		assert.True(t, isForwardAuth)
		assert.Equal(t, &envoy_service_auth_v2.AttributeContext_HttpRequest{
			Method: "GET",
			Path:   "/some/path?qs=1",
			Host:   "example.com",
			Scheme: "https",
		}, checkReq.Attributes.Request.Http)
	})
	t.Run("disabled", func(t *testing.T) {
		a := new(Authorize)
		a.currentOptions.Store(config.Options{
			ForwardAuthURL: nil,
		})
		isForwardAuth := a.handleForwardAuth(checkReq)
		assert.False(t, isForwardAuth)
	})
}

func Test_refreshSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			Authorization string
		}{
			Authorization: r.Header.Get("Authorization"),
		})
	}))
	defer srv.Close()

	sharedKey := make([]byte, 32)
	a := new(Authorize)
	a.currentOptions.Store(config.Options{
		AuthenticateURL: mustParseURL(srv.URL),
		SharedKey:       base64.StdEncoding.EncodeToString(sharedKey),
	})

	newSession, err := a.refreshSession(context.Background(), []byte("ABCD"))
	assert.NoError(t, err)
	assert.Equal(t, `{"Authorization":"Pomerium ABCD"}`, strings.TrimSpace(string(newSession)))
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func TestAuthorize_Check(t *testing.T) {
	// golden policy
	p := config.Policy{
		From:         "http://test.example.com",
		To:           "http://localhost",
		AllowedUsers: []string{"bob@example.com"},
	}
	err := p.Validate()
	if err != nil {
		t.Fatal(err)
	}
	ps := []config.Policy{p}

	type user struct {
		// Standard claims (as specified in RFC 7519).
		jwt.Claims
		// Pomerium claims (not standard claims)
		Email             string   `json:"email"`
		Groups            []string `json:"groups,omitempty"`
		User              string   `json:"user,omitempty"`
		ImpersonateEmail  string   `json:"impersonate_email,omitempty"`
		ImpersonateGroups []string `json:"impersonate_groups,omitempty"`
	}

	tests := []struct {
		name       string
		ctx        context.Context
		sk         string
		inUser     string
		inExpiry   time.Time
		inIssuer   string
		inAudience string
		in         *envoy_service_auth_v2.CheckRequest
		want       string
		wantErr    bool
	}{
		{"good",
			context.TODO(),
			cryptutil.NewBase64Key(),
			"bob@example.com",
			time.Now().Add(1 * time.Hour),
			"authN.example.com",
			"test.example.com",
			nil,
			"OK",
			false},
		{"bad user, alice",
			context.TODO(),
			cryptutil.NewBase64Key(),
			"alice@example.com",
			time.Now().Add(1 * time.Hour),
			"authN.example.com",
			"test.example.com",
			nil,
			"Access Denied",
			false},
		{"expired",
			context.TODO(),
			cryptutil.NewBase64Key(),
			"bob@example.com",
			time.Now().Add(-1 * time.Hour),
			"authN.example.com",
			"test.example.com",
			nil,
			"Access Denied",
			false},
		{"bad audience",
			context.TODO(),
			cryptutil.NewBase64Key(),
			"bob@example.com",
			time.Now().Add(1 * time.Hour),
			"authN.example.com",
			"bad.example.com",
			nil,
			"Access Denied",
			false},
		{"bad issuer",
			context.TODO(),
			cryptutil.NewBase64Key(),
			"bob@example.com",
			time.Now().Add(1 * time.Hour),
			"bad.example.com",
			"test.example.com",
			nil,
			"OK",
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sa user
			sa.Expiry = jwt.NewNumericDate(tt.inExpiry)
			sa.IssuedAt = jwt.NewNumericDate(time.Now())
			sa.NotBefore = jwt.NewNumericDate(time.Now())
			sa.Email = tt.inUser
			sa.Subject = sa.Email
			sa.Issuer = tt.inIssuer
			sa.Audience = jwt.Audience{tt.inAudience}

			sharedKey := tt.sk

			encoder, err := jws.NewHS256Signer([]byte(sharedKey), tt.inIssuer)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := encoder.Marshal(sa)
			if err != nil {
				t.Fatal(err)
			}
			opts := config.Options{
				Policies:        ps,
				CookieName:      "_pomerium",
				AuthenticateURL: mustParseURL("https://authN.example.com"),
				SharedKey:       sharedKey}
			a, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			in := &envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Id:     "id-1234",
							Method: "GET",
							Headers: map[string]string{
								"accept": "text/json",
								"cookie": "_pomerium=" + string(raw),
							},
							Host:   "test.example.com",
							Scheme: "http",
							Body:   "BODY",
						},
					},
				},
			}
			got, err := a.Check(tt.ctx, in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize.Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got.Status.GetMessage(), tt.want); diff != "" {
				t.Errorf("Authorize.Check() = %v", diff)
			}
		})
	}
}
