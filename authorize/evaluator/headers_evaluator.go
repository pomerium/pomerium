package evaluator

import (
	"context"
	"fmt"
	"net/http"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
)

// HeadersRequest is the input to the headers.rego script.
type HeadersRequest struct {
	EnableGoogleCloudServerlessAuthentication bool                  `json:"enable_google_cloud_serverless_authentication"`
	EnableRoutingKey                          bool                  `json:"enable_routing_key"`
	Issuer                                    string                `json:"issuer"`
	Audience                                  string                `json:"audience"`
	KubernetesServiceAccountToken             string                `json:"kubernetes_service_account_token"`
	ToAudience                                string                `json:"to_audience"`
	Session                                   RequestSession        `json:"session"`
	ClientCertificate                         ClientCertificateInfo `json:"client_certificate"`
	SetRequestHeaders                         map[string]string     `json:"set_request_headers"`
}

// NewHeadersRequestFromPolicy creates a new HeadersRequest from a policy.
func NewHeadersRequestFromPolicy(policy *config.Policy, http RequestHTTP) (*HeadersRequest, error) {
	input := new(HeadersRequest)
	input.Audience = http.Hostname
	var issuerFormat string
	if policy != nil {
		issuerFormat = policy.JWTIssuerFormat
	}
	switch issuerFormat {
	case "", "hostOnly":
		input.Issuer = http.Hostname
	case "uri":
		input.Issuer = fmt.Sprintf("https://%s/", http.Hostname)
	default:
		return nil, fmt.Errorf("invalid issuer format: %q", policy.JWTIssuerFormat)
	}
	if policy != nil {
		input.EnableGoogleCloudServerlessAuthentication = policy.EnableGoogleCloudServerlessAuthentication
		input.EnableRoutingKey = policy.EnvoyOpts.GetLbPolicy() == envoy_config_cluster_v3.Cluster_RING_HASH ||
			policy.EnvoyOpts.GetLbPolicy() == envoy_config_cluster_v3.Cluster_MAGLEV
		var err error
		input.KubernetesServiceAccountToken, err = policy.GetKubernetesServiceAccountToken()
		if err != nil {
			return nil, err
		}
		for _, wu := range policy.To {
			input.ToAudience = "https://" + wu.URL.Hostname()
		}
		input.ClientCertificate = http.ClientCertificate
		input.SetRequestHeaders = policy.SetRequestHeaders
	}
	return input, nil
}

// HeadersResponse is the output from the headers.rego script.
type HeadersResponse struct {
	Headers http.Header
}

// A HeadersEvaluator evaluates the headers.rego script.
type HeadersEvaluator struct {
	store *store.Store
}

// NewHeadersEvaluator creates a new HeadersEvaluator.
func NewHeadersEvaluator(store *store.Store) *HeadersEvaluator {
	return &HeadersEvaluator{
		store: store,
	}
}

// Evaluate evaluates the headers.rego script.
func (e *HeadersEvaluator) Evaluate(ctx context.Context, req *HeadersRequest, options ...rego.EvalOption) (*HeadersResponse, error) {
	ectx := new(rego.EvalContext)
	for _, option := range options {
		option(ectx)
	}
	now := ectx.Time()
	if now.IsZero() {
		now = time.Now()
	}
	return newHeadersEvaluatorEvaluation(e, req, now).execute(ctx)
}
