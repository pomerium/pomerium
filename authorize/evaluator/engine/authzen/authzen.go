// Package authzen implements a PolicyEngine that delegates access
// decisions to an external Policy Decision Point speaking the OpenID
// AuthZEN Authorization API 1.0 (draft 01).
//
// See https://openid.net/specs/authorization-api-1_0-01.html.
package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// KindAuthZEN is the engine kind for the AuthZEN HTTP adapter.
const KindAuthZEN engine.Kind = "authzen"

// Default values used by New when fields on Config are unset.
const (
	DefaultTimeout      = 2 * time.Second
	DefaultEvaluatePath = "/access/v1/evaluation"
	DefaultSubjectType  = "user"
	DefaultResourceType = "pomerium_route"

	anonymousSubjectID = "anonymous"
)

// contentTypeJSON is the only request/response content type AuthZEN
// mandates.
const contentTypeJSON = "application/json"

// Sentinel errors returned by New and Evaluate.
var (
	ErrMissingEndpoint = errors.New("authzen: endpoint is required")
	ErrInvalidConfig   = errors.New("authzen: invalid configuration")
	ErrPDPRequest      = errors.New("authzen: PDP request failed")
	ErrPDPResponse     = errors.New("authzen: PDP returned an unexpected response")
)

// Config configures an AuthZEN PDP connection.
//
// It is also the shape the config layer unmarshals into when an operator
// sets engine_config under their policy_engine block.
type Config struct {
	// Endpoint is the base URL of the PDP (e.g. https://pdp.example.com).
	// The EvaluatePath is appended to form the full evaluation URL.
	Endpoint string `json:"endpoint" mapstructure:"endpoint"`
	// EvaluatePath is appended to Endpoint to form the evaluation URL.
	// Defaults to DefaultEvaluatePath.
	EvaluatePath string `json:"evaluate_path" mapstructure:"evaluate_path"`
	// AuthHeader is set verbatim as the HTTP Authorization header on each
	// request. Empty disables authentication.
	AuthHeader string `json:"auth_header" mapstructure:"auth_header"`
	// Timeout bounds each evaluation call. Defaults to DefaultTimeout.
	Timeout time.Duration `json:"timeout" mapstructure:"timeout"`
	// SubjectType is the AuthZEN subject.type used for authenticated
	// users. Defaults to DefaultSubjectType.
	SubjectType string `json:"subject_type" mapstructure:"subject_type"`
	// ResourceType is the AuthZEN resource.type. Defaults to
	// DefaultResourceType.
	ResourceType string `json:"resource_type" mapstructure:"resource_type"`
}

// withDefaults returns a copy of c with zero-valued fields replaced by
// package defaults.
func (c Config) withDefaults() Config {
	if c.EvaluatePath == "" {
		c.EvaluatePath = DefaultEvaluatePath
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.SubjectType == "" {
		c.SubjectType = DefaultSubjectType
	}
	if c.ResourceType == "" {
		c.ResourceType = DefaultResourceType
	}
	return c
}

// Engine is an AuthZEN-backed PolicyEngine.
type Engine struct {
	cfg    Config
	url    string
	client *http.Client
}

var _ engine.PolicyEngine = (*Engine)(nil)

// New creates a new Engine. It does not dial; the connection is
// established on first use so that authorize startup does not block on
// PDP availability.
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	if cfg.Endpoint == "" {
		return nil, ErrMissingEndpoint
	}
	url := strings.TrimRight(cfg.Endpoint, "/") + cfg.EvaluatePath
	return &Engine{
		cfg:    cfg,
		url:    url,
		client: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// Evaluate runs local pre-checks and, when needed, delegates to the
// AuthZEN PDP. Pre-checks return locally so that login redirect and
// WebAuthn flows remain available when the PDP is unreachable.
func (e *Engine) Evaluate(ctx context.Context, req *evaluator.Request) (*engine.Decision, error) {
	if dec, ok := preCheck(req); ok {
		return dec, nil
	}
	return e.callPDP(ctx, req)
}

// Close is a no-op; the engine owns an *http.Client whose lifetime is
// bound to the engine itself.
func (e *Engine) Close() error { return nil }

// callPDP performs the AuthZEN evaluation request and translates the
// response into an engine.Decision.
func (e *Engine) callPDP(ctx context.Context, req *evaluator.Request) (*engine.Decision, error) {
	body, err := json.Marshal(buildEvaluationRequest(req, e.cfg))
	if err != nil {
		return nil, fmt.Errorf("%w: encode body: %w", ErrPDPRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: new request: %w", ErrPDPRequest, err)
	}
	httpReq.Header.Set("Content-Type", contentTypeJSON)
	httpReq.Header.Set("Accept", contentTypeJSON)
	if e.cfg.AuthHeader != "" {
		httpReq.Header.Set("Authorization", e.cfg.AuthHeader)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPDPRequest, err)
	}
	defer resp.Body.Close()

	return readEvaluationResponse(resp)
}

// readEvaluationResponse parses an AuthZEN evaluation response.
//
// Per the spec, only HTTP 200 carries an authorization decision; any
// other status is a PDP-level error that we surface as ErrPDPResponse so
// the orchestrator returns a 5xx rather than silently denying.
func readEvaluationResponse(resp *http.Response) (*engine.Decision, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		return nil, fmt.Errorf("%w: status=%d body=%s", ErrPDPResponse, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != contentTypeJSON {
		return nil, fmt.Errorf("%w: unexpected content-type %q", ErrPDPResponse, resp.Header.Get("Content-Type"))
	}

	var er evaluationResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, fmt.Errorf("%w: decode body: %w", ErrPDPResponse, err)
	}
	if er.Decision {
		return allow(criteria.ReasonUserOK), nil
	}
	return deny(criteria.ReasonUserUnauthorized), nil
}

// preCheck returns a Decision and true when the request can be answered
// without consulting the PDP. It returns (nil, false) otherwise.
func preCheck(req *evaluator.Request) (*engine.Decision, bool) {
	switch {
	case req == nil, req.Policy == nil:
		return deny(criteria.ReasonRouteNotFound), true
	case req.IsInternal:
		return allow(criteria.ReasonPomeriumRoute), true
	case req.Session.ID == "" && !req.Policy.AllowPublicUnauthenticatedAccess:
		return deny(criteria.ReasonUserUnauthenticated), true
	}
	return nil, false
}

func allow(reasons ...criteria.Reason) *engine.Decision {
	return &engine.Decision{
		Allow: evaluator.NewRuleResult(true, reasons...),
		Deny:  evaluator.NewRuleResult(false),
	}
}

func deny(reasons ...criteria.Reason) *engine.Decision {
	return &engine.Decision{
		Allow: evaluator.NewRuleResult(false),
		Deny:  evaluator.NewRuleResult(true, reasons...),
	}
}

func init() {
	engine.Register(KindAuthZEN, true, factory)
}

// factory is the registry callback that builds an AuthZEN engine from a
// raw FactoryConfig.
//
// EngineConfig may arrive either as a *Config (set programmatically) or
// as a map[string]any (produced by mapstructure / YAML). We accept both.
func factory(cfg engine.FactoryConfig) (engine.PolicyEngine, error) {
	c, err := decodeConfig(cfg.EngineConfig)
	if err != nil {
		return nil, err
	}
	return New(*c)
}

// decodeConfig converts an opaque engine config blob into a *Config.
//
// Supported shapes:
//   - nil               → defaults
//   - *Config / Config  → used directly
//   - map[string]any    → JSON-encoded and re-decoded into Config
func decodeConfig(raw any) (*Config, error) {
	switch v := raw.(type) {
	case nil:
		c := Config{}
		return &c, nil
	case *Config:
		c := *v
		return &c, nil
	case Config:
		c := v
		return &c, nil
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		c := Config{}
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		return &c, nil
	default:
		return nil, fmt.Errorf("%w: unsupported config type %T", ErrInvalidConfig, raw)
	}
}
