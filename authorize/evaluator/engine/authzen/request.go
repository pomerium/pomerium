package authzen

import (
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

// subject is the AuthZEN Subject object.
type subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// resource is the AuthZEN Resource object.
type resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// action is the AuthZEN Action object.
type action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// evaluationRequest is the AuthZEN Access Evaluation Request.
type evaluationRequest struct {
	Subject  subject        `json:"subject"`
	Resource resource       `json:"resource"`
	Action   action         `json:"action"`
	Context  map[string]any `json:"context,omitempty"`
}

// evaluationResponse is the AuthZEN Access Evaluation Response.
type evaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// buildEvaluationRequest constructs an AuthZEN request from req and cfg.
func buildEvaluationRequest(req *evaluator.Request, cfg Config) evaluationRequest {
	return evaluationRequest{
		Subject:  buildSubject(req, cfg),
		Resource: buildResource(req, cfg),
		Action:   buildAction(req),
		Context:  buildContext(req),
	}
}

func buildSubject(req *evaluator.Request, cfg Config) subject {
	id := req.Session.UserID
	if id == "" {
		id = anonymousSubjectID
	}
	props := map[string]any{}
	if req.Session.ID != "" {
		props["session_id"] = req.Session.ID
	}
	if req.Policy != nil {
		props["route_from"] = req.Policy.From
	}
	if len(props) == 0 {
		props = nil
	}
	return subject{Type: cfg.SubjectType, ID: id, Properties: props}
}

func buildResource(req *evaluator.Request, cfg Config) resource {
	id := ""
	if req.Policy != nil {
		// RouteID errors only for incomplete policies that the orchestrator
		// will already have rejected via the route-not-found pre-check.
		id, _ = req.Policy.RouteID()
	}
	props := map[string]any{
		"host":              req.HTTP.Host,
		"path":              req.HTTP.Path,
		"method":            req.HTTP.Method,
		"ip":                req.HTTP.IP,
		"client_cert_valid": clientCertValid(req),
	}
	if req.Policy != nil {
		props["route_from"] = req.Policy.From
	}
	return resource{Type: cfg.ResourceType, ID: id, Properties: props}
}

func buildAction(req *evaluator.Request) action {
	name := canonicalAction(req.HTTP.Method)
	return action{
		Name:       name,
		Properties: map[string]any{"method": req.HTTP.Method},
	}
}

// canonicalAction maps an HTTP method onto an AuthZEN common action name.
// Unknown methods become "can_access" so policies don't have to enumerate
// every verb.
func canonicalAction(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "can_read"
	case http.MethodPost:
		return "can_create"
	case http.MethodPut, http.MethodPatch:
		return "can_update"
	case http.MethodDelete:
		return "can_delete"
	default:
		return "can_access"
	}
}

func buildContext(req *evaluator.Request) map[string]any {
	ctx := map[string]any{}
	if req.HTTP.IP != "" {
		ctx["ip"] = req.HTTP.IP
	}
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

// clientCertValid returns the precomputed client-certificate validity, or
// true when no value has been set (the OPA path treats a missing setting
// as "no client cert required for this route").
func clientCertValid(req *evaluator.Request) bool {
	if req.PrecomputedClientCertValid == nil {
		return true
	}
	return *req.PrecomputedClientCertValid
}
