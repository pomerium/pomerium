package evaluator

import (
	"context"
	"fmt"
	"net/http"

	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/authorize/evaluator/opa"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// HeadersRequest is the input to the headers.rego script.
type HeadersRequest struct {
	EnableGoogleCloudServerlessAuthentication bool           `json:"enable_google_cloud_serverless_authentication"`
	FromAudience                              string         `json:"from_audience"`
	KubernetesServiceAccountToken             string         `json:"kubernetes_service_account_token"`
	ToAudience                                string         `json:"to_audience"`
	Session                                   RequestSession `json:"session"`
}

// NewHeadersRequestFromPolicy creates a new HeadersRequest from a policy.
func NewHeadersRequestFromPolicy(policy *config.Policy) *HeadersRequest {
	input := new(HeadersRequest)
	input.EnableGoogleCloudServerlessAuthentication = policy.EnableGoogleCloudServerlessAuthentication
	if u, err := urlutil.ParseAndValidateURL(policy.From); err == nil {
		input.FromAudience = u.Hostname()
	}
	input.KubernetesServiceAccountToken = policy.KubernetesServiceAccountToken
	for _, wu := range policy.To {
		input.ToAudience = wu.URL.Hostname()
	}
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
func NewHeadersEvaluator(ctx context.Context, store *Store) (*HeadersEvaluator, error) {
	headersSrc, err := opa.FS.ReadFile("policy/headers.rego")
	if err != nil {
		return nil, err
	}

	r := rego.New(
		rego.Store(store),
		rego.Module("pomerium.headers", string(headersSrc)),
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
	rs, err := e.q.Eval(ctx, rego.EvalInput(req))
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
