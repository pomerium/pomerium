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
	"github.com/pomerium/pomerium/internal/testutil"
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

	actual, err := a.getEvaluatorRequestFromCheckRequest(context.Background(),
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
		HTTP: evaluator.NewRequestHTTP(
			http.MethodGet,
			mustParseURL("http://example.com/some/path?qs=1"),
			map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			evaluator.ClientCertificateInfo{
				Presented:     true,
				Leaf:          certPEM[1:] + "\n",
				Intermediates: "",
			},
			"",
		),
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

	actual, err := a.getEvaluatorRequestFromCheckRequest(context.Background(),
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
		HTTP: evaluator.NewRequestHTTP(
			http.MethodGet,
			mustParseURL("http://example.com/some/path?qs=1"),
			map[string]string{
				"Accept":            "text/html",
				"X-Forwarded-Proto": "https",
			},
			evaluator.ClientCertificateInfo{},
			"",
		),
	}
	assert.Equal(t, expect, actual)
}

func Test_getClientCertificateInfo(t *testing.T) {
	const leafPEM = `-----BEGIN CERTIFICATE-----
MIIBZTCCAQugAwIBAgICEAEwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAxMPSW50ZXJt
ZWRpYXRlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMB8x
HTAbBgNVBAMTFENsaWVudCBjZXJ0aWZpY2F0ZSAxMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAESly1cwEbcxaJBl6qAhrX1k7vejTFNE2dEbrTMpUYMl86GEWdsDYN
KSa/1wZCowPy82gPGjfAU90odkqJOusCQqM4MDYwEwYDVR0lBAwwCgYIKwYBBQUH
AwIwHwYDVR0jBBgwFoAU6Qb7nEl2XHKpf/QLL6PENsHFqbowCgYIKoZIzj0EAwID
SAAwRQIgXREMUz81pYwJCMLGcV0ApaXIUap1V5n1N4VhyAGxGLYCIQC8p/LwoSgu
71H3/nCi5MxsECsvVtsmHIfwXt0wulQ1TA==
-----END CERTIFICATE-----
`
	const intermediatePEM = `-----BEGIN CERTIFICATE-----
MIIBYzCCAQigAwIBAgICEAEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMHUm9vdCBD
QTAiGA8wMDAxMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjAaMRgwFgYDVQQD
Ew9JbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYaTr9
uH4LpEp541/2SlKrdQZwNns+NHY/ftm++NhMDUn+izzNbPZ5aPT6VBs4Q6vbgfkK
kDaBpaKzb+uOT+o1o0IwQDAdBgNVHQ4EFgQU6Qb7nEl2XHKpf/QLL6PENsHFqbow
HwYDVR0jBBgwFoAUiQ3r61y+vxDn6PMWZrpISr67HiQwCgYIKoZIzj0EAwIDSQAw
RgIhAMvdURs28uib2QwSMnqJjKasMb30yrSJvTiSU+lcg97/AiEA+6GpioM0c221
n/XNKVYEkPmeXHRoz9ZuVDnSfXKJoHE=
-----END CERTIFICATE-----
`
	const rootPEM = `-----BEGIN CERTIFICATE-----
MIIBNzCB36ADAgECAgIQADAKBggqhkjOPQQDAjASMRAwDgYDVQQDEwdSb290IENB
MCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBIxEDAOBgNVBAMT
B1Jvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6q0mTvm29xasq7Lwk
aRGb2S/LkQFsAwaCXohSNvonCQHRMCRvA1IrQGk/oyBS5qrDoD9/7xkcVYHuTv5D
CbtuoyEwHzAdBgNVHQ4EFgQUiQ3r61y+vxDn6PMWZrpISr67HiQwCgYIKoZIzj0E
AwIDRwAwRAIgF1ux0ridbN+bo0E3TTcNY8Xfva7yquYRMmEkfbGvSb0CIDqK80B+
fYCZHo3CID0gRSemaQ/jYMgyeBFrHIr6icZh
-----END CERTIFICATE-----
`

	cases := []struct {
		label       string
		presented   bool
		chain       string
		expected    evaluator.ClientCertificateInfo
		expectedLog string
	}{
		{
			"not presented",
			false,
			"",
			evaluator.ClientCertificateInfo{},
			"",
		},
		{
			"presented",
			true,
			url.QueryEscape(leafPEM),
			evaluator.ClientCertificateInfo{
				Presented: true,
				Leaf:      leafPEM,
			},
			"",
		},
		{
			"presented with intermediates",
			true,
			url.QueryEscape(leafPEM + intermediatePEM + rootPEM),
			evaluator.ClientCertificateInfo{
				Presented:     true,
				Leaf:          leafPEM,
				Intermediates: intermediatePEM + rootPEM,
			},
			"",
		},
		{
			"invalid chain URL encoding",
			false,
			"invalid%URL%encoding",
			evaluator.ClientCertificateInfo{},
			`{"chain":"invalid%URL%encoding","error":"invalid URL escape \"%UR\"","level":"error","message":"received unexpected client certificate \"chain\" value"}`,
		},
		{
			"invalid chain PEM encoding",
			true,
			"not valid PEM data",
			evaluator.ClientCertificateInfo{
				Presented: true,
			},
			`{"chain":"not valid PEM data","level":"error","message":"received unexpected client certificate \"chain\" value (no PEM block found)"}`,
		},
	}

	ctx := context.Background()
	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			metadata := &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"presented": structpb.NewBoolValue(c.presented),
					"chain":     structpb.NewStringValue(c.chain),
				},
			}
			var info evaluator.ClientCertificateInfo
			logOutput := testutil.CaptureLogs(t, func() {
				info = getClientCertificateInfo(ctx, metadata)
			})
			assert.Equal(t, c.expected, info)
			assert.Contains(t, logOutput, c.expectedLog)
		})
	}
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

func mustParseURL(rawURL string) url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return *u
}
