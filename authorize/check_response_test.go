package authorize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/testutil"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

func TestAuthorize_handleResult(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.DataBrokerURLString = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="

	hpkePrivateKey, err := opt.GetHPKEPrivateKey()
	require.NoError(t, err)

	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opt.AuthenticateURLString = authnSrv.URL

	a, err := New(&config.Config{Options: opt})
	require.NoError(t, err)

	t.Run("user-unauthenticated", func(t *testing.T) {
		res, err := a.handleResult(context.Background(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))

		res, err = a.handleResult(context.Background(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Deny: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("device-unauthenticated", func(t *testing.T) {
		res, err := a.handleResult(context.Background(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonDeviceUnauthenticated),
			})
		assert.NoError(t, err)
		assert.Equal(t, 302, int(res.GetDeniedResponse().GetStatus().GetCode()))

		t.Run("webauthn path", func(t *testing.T) {
			res, err := a.handleResult(context.Background(),
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
}

func TestAuthorize_okResponse(t *testing.T) {
	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
			To:     mustParseWeightedURLs(t, "https://to.example.com"),
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
		JWTClaimsHeaders: config.NewJWTClaimHeaders("email"),
	}
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: atomicutil.NewValue(new(authorizeState))}
	a.currentOptions.Store(opt)
	a.store = store.New()
	pe, err := newPolicyEvaluator(opt, a.store)
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := a.okResponse(tc.reply.Headers)
			assert.Equal(t, tc.want.Status.Code, got.Status.Code)
			assert.Equal(t, tc.want.Status.Message, got.Status.Message)
			want, _ := protojson.Marshal(tc.want.GetOkResponse())
			testutil.AssertProtoJSONEqual(t, string(want), got.GetOkResponse())
		})
	}
}

func TestAuthorize_deniedResponse(t *testing.T) {
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: atomicutil.NewValue(new(authorizeState))}
	a.currentOptions.Store(&config.Options{
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	})

	tests := []struct {
		name    string
		in      *envoy_service_auth_v3.CheckRequest
		code    int32
		reason  string
		headers map[string]string
		want    *envoy_service_auth_v3.CheckResponse
	}{
		{
			"html denied",
			nil,
			http.StatusBadRequest,
			"Access Denied",
			nil,
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
				HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
					DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
						Status: &envoy_type_v3.HttpStatus{
							Code: envoy_type_v3.StatusCode(codes.InvalidArgument),
						},
						Headers: []*envoy_config_core_v3.HeaderValueOption{
							mkHeader("Content-Type", "text/html; charset=UTF-8"),
							mkHeader("X-Pomerium-Intercepted-Response", "true"),
						},
						Body: "Access Denied",
					},
				},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := a.deniedResponse(context.TODO(), tc.in, tc.code, tc.reason, tc.headers)
			require.NoError(t, err)
			assert.Equal(t, tc.want.Status.Code, got.Status.Code)
			assert.Equal(t, tc.want.Status.Message, got.Status.Message)
			testutil.AssertProtoEqual(t, tc.want.GetDeniedResponse().GetHeaders(), got.GetDeniedResponse().GetHeaders())
		})
	}
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func TestRequireLogin(t *testing.T) {
	t.Parallel()

	opt := config.NewDefaultOptions()
	opt.DataBrokerURLString = "https://databroker.example.com"
	opt.SharedKey = "E8wWIMnihUx+AUfRegAQDNs8eRb3UrB5G3zlJW9XJDM="
	opt.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUJlMFRxbXJkSXBZWE03c3pSRERWYndXOS83RWJHVWhTdFFJalhsVHNXM1BvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFb0xaRDI2bEdYREhRQmhhZkdlbEVmRDdlNmYzaURjWVJPVjdUbFlIdHF1Y1BFL2hId2dmYQpNY3FBUEZsRmpueUpySXJhYTFlQ2xZRTJ6UktTQk5kNXBRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="

	hpkePrivateKey, err := opt.GetHPKEPrivateKey()
	require.NoError(t, err)

	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opt.AuthenticateURLString = authnSrv.URL

	a, err := New(&config.Config{Options: opt})
	require.NoError(t, err)

	t.Run("accept empty", func(t *testing.T) {
		res, err := a.requireLoginResponse(context.Background(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{})
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
	t.Run("accept html", func(t *testing.T) {
		res, err := a.requireLoginResponse(context.Background(),
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
		res, err := a.requireLoginResponse(context.Background(),
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
