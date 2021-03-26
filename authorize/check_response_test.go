package authorize

import (
	"html/template"
	"net/http"
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
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestAuthorize_okResponse(t *testing.T) {
	opt := &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
		JWTClaimsHeaders: config.NewJWTClaimHeaders("email"),
	}
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0})
	a.state.Load().encoder = encoder
	a.currentOptions.Store(opt)
	a.store = evaluator.NewStoreFromProtos(0,
		&session.Session{
			Id:     "SESSION_ID",
			UserId: "USER_ID",
		},
		&user.User{
			Id:    "USER_ID",
			Name:  "foo",
			Email: "foo@example.com",
		},
	)
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
			&evaluator.Result{Status: 0, Message: "ok"},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
			},
		},
		{
			"ok reply with k8s svc",
			&evaluator.Result{
				Status:  0,
				Message: "ok",
				MatchingPolicy: &config.Policy{
					KubernetesServiceAccountToken: "k8s-svc-account",
				},
			},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
			},
		},
		{
			"ok reply with k8s svc impersonate",
			&evaluator.Result{
				Status:  0,
				Message: "ok",
				MatchingPolicy: &config.Policy{
					KubernetesServiceAccountToken: "k8s-svc-account",
				},
			},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
			},
		},
		{
			"ok reply with jwt claims header",
			&evaluator.Result{
				Status:  0,
				Message: "ok",
			},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := a.okResponse(tc.reply)
			assert.Equal(t, tc.want.Status.Code, got.Status.Code)
			assert.Equal(t, tc.want.Status.Message, got.Status.Message)
			want, _ := protojson.Marshal(tc.want.GetOkResponse())
			testutil.AssertProtoJSONEqual(t, string(want), got.GetOkResponse())
		})
	}
}

func TestAuthorize_deniedResponse(t *testing.T) {
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
	a.templates = template.Must(frontend.NewTemplates())

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
							mkHeader("Content-Type", "text/html", false),
						},
						Body: "Access Denied",
					},
				},
			},
		},
		{
			"plain text denied",
			&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Headers: map[string]string{},
						},
					},
				},
			},
			http.StatusBadRequest,
			"Access Denied",
			map[string]string{},
			&envoy_service_auth_v3.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
				HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
					DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
						Status: &envoy_type_v3.HttpStatus{
							Code: envoy_type_v3.StatusCode(codes.InvalidArgument),
						},
						Headers: []*envoy_config_core_v3.HeaderValueOption{
							mkHeader("Content-Type", "text/plain", false),
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
			got, err := a.deniedResponse(tc.in, tc.code, tc.reason, tc.headers)
			require.NoError(t, err)
			assert.Equal(t, tc.want.Status.Code, got.Status.Code)
			assert.Equal(t, tc.want.Status.Message, got.Status.Message)
			assert.Equal(t, tc.want.GetDeniedResponse().GetHeaders(), got.GetDeniedResponse().GetHeaders())
		})
	}
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
