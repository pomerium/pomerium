package authorize

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
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
		AuthenticateURL: mustParseURL("https://authenticate.example.com"),
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
		JWTClaimsHeaders: []string{"email"},
	}
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0})
	a.state.Load().encoder = encoder
	a.currentOptions.Store(opt)
	a.store = evaluator.NewStoreFromProtos(
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
	validJWT, _ := pe.SignedJWT(pe.JWTPayload(&evaluator.Request{
		HTTP: evaluator.RequestHTTP{URL: "https://example.com"},
		Session: evaluator.RequestSession{
			ID: "SESSION_ID",
		},
	}))

	originalGCPIdentityDocURL := gcpIdentityDocURL
	defer func() {
		gcpIdentityDocURL = originalGCPIdentityDocURL
		gcpIdentityNow = time.Now
	}()

	now := time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC)
	gcpIdentityNow = func() time.Time {
		return now
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(now.Format(time.RFC3339)))
	}))
	defer srv.Close()
	gcpIdentityDocURL = srv.URL

	tests := []struct {
		name  string
		reply *evaluator.Result
		want  *envoy_service_auth_v2.CheckResponse
	}{
		{
			"ok reply",
			&evaluator.Result{Status: 0, Message: "ok", SignedJWT: "valid-signed-jwt"},
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v2.OkHttpResponse{
						Headers: []*envoy_api_v2_core.HeaderValueOption{
							mkHeader("x-pomerium-jwt-assertion", "valid-signed-jwt", false),
						},
					},
				},
			},
		},
		{
			"ok reply with k8s svc",
			&evaluator.Result{
				Status:    0,
				Message:   "ok",
				SignedJWT: "valid-signed-jwt",
				MatchingPolicy: &config.Policy{
					KubernetesServiceAccountToken: "k8s-svc-account",
				},
			},
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v2.OkHttpResponse{
						Headers: []*envoy_api_v2_core.HeaderValueOption{
							mkHeader("x-pomerium-jwt-assertion", "valid-signed-jwt", false),
							mkHeader("Authorization", "Bearer k8s-svc-account", false),
						},
					},
				},
			},
		},
		{
			"ok reply with k8s svc impersonate",
			&evaluator.Result{
				Status:    0,
				Message:   "ok",
				SignedJWT: "valid-signed-jwt",
				MatchingPolicy: &config.Policy{
					KubernetesServiceAccountToken: "k8s-svc-account",
				},
				UserEmail:  "foo@example.com",
				UserGroups: []string{"admin", "test"},
			},
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v2.OkHttpResponse{
						Headers: []*envoy_api_v2_core.HeaderValueOption{
							mkHeader("x-pomerium-jwt-assertion", "valid-signed-jwt", false),
							mkHeader("Authorization", "Bearer k8s-svc-account", false),
							mkHeader("Impersonate-User", "foo@example.com", false),
							mkHeader("Impersonate-Group", "admin", false),
							mkHeader("Impersonate-Group", "test", true),
						},
					},
				},
			},
		},
		{
			"ok reply with google cloud serverless",
			&evaluator.Result{
				Status:    0,
				Message:   "ok",
				SignedJWT: "valid-signed-jwt",
				MatchingPolicy: &config.Policy{
					EnableGoogleCloudServerlessAuthentication: true,
					To: mustParseWeightedURLs(t, "https://example.com"),
				},
			},
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v2.OkHttpResponse{
						Headers: []*envoy_api_v2_core.HeaderValueOption{
							mkHeader("x-pomerium-jwt-assertion", "valid-signed-jwt", false),
							mkHeader("Authorization", "Bearer 2020-01-01T01:00:00Z", false),
						},
					},
				},
			},
		},
		{
			"ok reply with jwt claims header",
			&evaluator.Result{
				Status:    0,
				Message:   "ok",
				SignedJWT: validJWT,
			},
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: 0, Message: "ok"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v2.OkHttpResponse{
						Headers: []*envoy_api_v2_core.HeaderValueOption{
							mkHeader("x-pomerium-claim-email", "foo@example.com", false),
							mkHeader("x-pomerium-jwt-assertion", validJWT, false),
						},
					},
				},
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
		in      *envoy_service_auth_v2.CheckRequest
		code    int32
		reason  string
		headers map[string]string
		want    *envoy_service_auth_v2.CheckResponse
	}{
		{
			"html denied",
			nil,
			http.StatusBadRequest,
			"Access Denied",
			nil,
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
					DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
						Status: &envoy_type.HttpStatus{
							Code: envoy_type.StatusCode(codes.InvalidArgument),
						},
						Headers: []*envoy_api_v2_core.HeaderValueOption{
							mkHeader("Content-Type", "text/html", false),
						},
						Body: "Access Denied",
					},
				},
			},
		},
		{
			"plain text denied",
			&envoy_service_auth_v2.CheckRequest{
				Attributes: &envoy_service_auth_v2.AttributeContext{
					Request: &envoy_service_auth_v2.AttributeContext_Request{
						Http: &envoy_service_auth_v2.AttributeContext_HttpRequest{
							Headers: map[string]string{},
						},
					},
				},
			},
			http.StatusBadRequest,
			"Access Denied",
			map[string]string{},
			&envoy_service_auth_v2.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "Access Denied"},
				HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
					DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
						Status: &envoy_type.HttpStatus{
							Code: envoy_type.StatusCode(codes.InvalidArgument),
						},
						Headers: []*envoy_api_v2_core.HeaderValueOption{
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
