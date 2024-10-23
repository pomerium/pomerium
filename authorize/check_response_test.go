package authorize

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/testutil"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
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
	t.Run("invalid-client-certificate", func(t *testing.T) {
		// Even if the user is unauthenticated, if a client certificate was required and an invalid
		// certificate was provided, access should be denied (no login redirect).
		res, err := a.handleResult(context.Background(),
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
		res, err := a.handleResult(context.Background(),
			&envoy_service_auth_v3.CheckRequest{},
			&evaluator.Request{},
			&evaluator.Result{
				Allow: evaluator.NewRuleResult(false, criteria.ReasonUserUnauthenticated),
				Deny:  evaluator.NewRuleResult(true, criteria.ReasonClientCertificateRequired),
			})
		assert.NoError(t, err)
		assert.Equal(t, 495, int(res.GetDeniedResponse().GetStatus().GetCode()))
	})
}

func TestAuthorize_okResponse(t *testing.T) {
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
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: atomicutil.NewValue(new(authorizeState))}
	a.currentOptions.Store(opt)
	a.store = store.New()
	pe, err := newPolicyEvaluator(opt, a.store, nil)
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
	t.Parallel()

	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: atomicutil.NewValue(new(authorizeState))}
	a.currentOptions.Store(&config.Options{
		Policies: []config.Policy{{
			From: "https://example.com",
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
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

	t.Run("grpc-web", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ctx = requestid.WithValue(ctx, "REQUESTID")

		res, err := a.deniedResponse(ctx, &envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Headers: map[string]string{
							"Accept": "application/grpc-web-text",
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
						"header": { "key": "grpc-status", "value": "16" }
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": { "key": "grpc-message", "value": "Unauthenticated" }
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
		ctx := context.Background()
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
		ctx := context.Background()
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
