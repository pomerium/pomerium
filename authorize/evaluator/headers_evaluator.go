package evaluator

import (
	"context"
	"fmt"
	"net/http"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/authorize/evaluator/opa"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// HeadersRequest is the input to the headers.rego script.
type HeadersRequest struct {
	EnableGoogleCloudServerlessAuthentication bool           `json:"enable_google_cloud_serverless_authentication"`
	EnableRoutingKey                          bool           `json:"enable_routing_key"`
	Issuer                                    string         `json:"issuer"`
	KubernetesServiceAccountToken             string         `json:"kubernetes_service_account_token"`
	ToAudience                                string         `json:"to_audience"`
	Session                                   RequestSession `json:"session"`
	PassAccessToken                           bool           `json:"pass_access_token"`
	PassIDToken                               bool           `json:"pass_id_token"`
}

// NewHeadersRequestFromPolicy creates a new HeadersRequest from a policy.
func NewHeadersRequestFromPolicy(policy *config.Policy) *HeadersRequest {
	input := new(HeadersRequest)
	input.EnableGoogleCloudServerlessAuthentication = policy.EnableGoogleCloudServerlessAuthentication
	input.EnableRoutingKey = policy.EnvoyOpts.GetLbPolicy() == envoy_config_cluster_v3.Cluster_RING_HASH ||
		policy.EnvoyOpts.GetLbPolicy() == envoy_config_cluster_v3.Cluster_MAGLEV
	if u, err := urlutil.ParseAndValidateURL(policy.From); err == nil {
		input.Issuer = u.Hostname()
	}
	input.KubernetesServiceAccountToken = policy.KubernetesServiceAccountToken
	for _, wu := range policy.To {
		input.ToAudience = "https://" + wu.URL.Hostname()
	}
	input.PassAccessToken = policy.GetSetAuthorizationHeader() == configpb.Route_ACCESS_TOKEN
	input.PassIDToken = policy.GetSetAuthorizationHeader() == configpb.Route_ID_TOKEN
	return input
}

// HeadersResponse is the output from the headers.rego script.
type HeadersResponse struct {
	Headers http.Header
}

// A HeadersEvaluator evaluates the headers.rego script.
type HeadersEvaluator struct {
	q rego.PreparedEvalQuery
}

// NewHeadersEvaluator creates a new HeadersEvaluator.
func NewHeadersEvaluator(ctx context.Context, store *store.Store) (*HeadersEvaluator, error) {
	r := rego.New(
		rego.Store(store),
		rego.Module("pomerium.headers", opa.HeadersRego),
		rego.Query("result = data.pomerium.headers"),
		getGoogleCloudServerlessHeadersRegoOption,
		store.GetDataBrokerRecordOption(),
	)

	q, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	return &HeadersEvaluator{
		q: q,
	}, nil
}

// Evaluate evaluates the headers.rego script.
func (e *HeadersEvaluator) Evaluate(ctx context.Context, req *HeadersRequest) (*HeadersResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.HeadersEvaluator.Evaluate")
	defer span.End()
	rs, err := safeEval(ctx, e.q, rego.EvalInput(req))
	if err != nil {
		return nil, fmt.Errorf("authorize: error evaluating headers.rego: %w", err)
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("authorize: unexpected empty result from evaluating headers.rego")
	}

	return &HeadersResponse{
		Headers: e.getHeader(rs[0].Bindings),
	}, nil
}

func (e *HeadersEvaluator) getHeader(vars rego.Vars) http.Header {
	h := make(http.Header)

	m, ok := vars["result"].(map[string]interface{})
	if !ok {
		return h
	}

	m, ok = m["identity_headers"].(map[string]interface{})
	if !ok {
		return h
	}

	for k := range m {
		vs, ok := m[k].([]interface{})
		if !ok {
			continue
		}
		for _, v := range vs {
			h.Add(k, fmt.Sprintf("%v", v))
		}
	}
	return h
}
