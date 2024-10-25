package evaluator

import (
	"context"
	"fmt"
	"net/http"
	"os"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/pomerium/pomerium/authorize/evaluator/opa"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// HeadersRequest is the input to the headers.rego script.
type HeadersRequest struct {
	EnableGoogleCloudServerlessAuthentication bool                  `json:"enable_google_cloud_serverless_authentication"`
	EnableRoutingKey                          bool                  `json:"enable_routing_key"`
	Issuer                                    string                `json:"issuer"`
	KubernetesServiceAccountToken             string                `json:"kubernetes_service_account_token"`
	ToAudience                                string                `json:"to_audience"`
	Session                                   RequestSession        `json:"session"`
	ClientCertificate                         ClientCertificateInfo `json:"client_certificate"`
	SetRequestHeaders                         map[string]string     `json:"set_request_headers"`
}

// NewHeadersRequestFromPolicy creates a new HeadersRequest from a policy.
func NewHeadersRequestFromPolicy(policy *config.Policy, http RequestHTTP) (*HeadersRequest, error) {
	input := new(HeadersRequest)
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

var variableSubstitutionFunctionRegoOption = rego.Function2(&rego.Function{
	Name: "pomerium.variable_substitution",
	Decl: types.NewFunction(
		types.Args(
			types.Named("input_string", types.S),
			types.Named("replacements",
				types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))),
		),
		types.Named("output", types.S),
	),
}, func(_ rego.BuiltinContext, op1 *ast.Term, op2 *ast.Term) (*ast.Term, error) {
	inputString, ok := op1.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("invalid input_string type: %T", op1.Value)
	}

	replacements, ok := op2.Value.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("invalid replacements type: %T", op2.Value)
	}

	var err error
	output := os.Expand(string(inputString), func(key string) string {
		if key == "$" {
			return "$" // allow a dollar sign to be escaped using $$
		}
		r := replacements.Get(ast.StringTerm(key))
		if r == nil {
			return ""
		}
		s, ok := r.Value.(ast.String)
		if !ok {
			err = fmt.Errorf("invalid replacement value type for key %q: %T", key, r.Value)
		}
		return string(s)
	})
	if err != nil {
		return nil, err
	}
	return ast.StringTerm(output), nil
})

// A HeadersEvaluator evaluates the headers.rego script.
type HeadersEvaluator struct {
	q rego.PreparedEvalQuery
}

// NewHeadersEvaluator creates a new HeadersEvaluator.
func NewHeadersEvaluator(ctx context.Context, store *store.Store, options ...func(rego *rego.Rego)) (*HeadersEvaluator, error) {
	r := rego.New(append([]func(*rego.Rego){
		rego.Store(store),
		rego.Module("pomerium.headers", opa.HeadersRego),
		rego.Query("result := data.pomerium.headers"),
		rego.EnablePrintStatements(true),
		getGoogleCloudServerlessHeadersRegoOption,
		variableSubstitutionFunctionRegoOption,
		store.GetDataBrokerRecordOption(),
		rego.SetRegoVersion(ast.RegoV1),
	}, options...)...)

	q, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	return &HeadersEvaluator{
		q: q,
	}, nil
}

// Evaluate evaluates the headers.rego script.
func (e *HeadersEvaluator) Evaluate(ctx context.Context, req *HeadersRequest, options ...rego.EvalOption) (*HeadersResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.HeadersEvaluator.Evaluate")
	defer span.End()
	rs, err := safeEval(ctx, e.q, append([]rego.EvalOption{rego.EvalInput(req)}, options...)...)
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

	m, ok := vars["result"].(map[string]any)
	if !ok {
		return h
	}

	m, ok = m["identity_headers"].(map[string]any)
	if !ok {
		return h
	}

	for k := range m {
		vs, ok := m[k].([]any)
		if !ok {
			continue
		}
		for _, v := range vs {
			h.Add(k, fmt.Sprintf("%v", v))
		}
	}
	return h
}
