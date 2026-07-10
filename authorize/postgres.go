package authorize

import (
	"context"
	"errors"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/postgresproxy"
)

type PostgresRequest struct {
	Hostname         string
	SessionID        string
	SessionBindingID string
	SourceAddress    string
	ClientCertPEM    string
	// ProtocolSession is the session marked by the PostgreSQL protocol server
	// after its TLS-derived identity request succeeds. Callers cannot mint the
	// marker carried by this object.
	ProtocolSession *postgresproxy.Session
	// RouteRevision is an internal config-convergence guard. It is never copied
	// into evaluator input or authorization logs.
	RouteRevision string
	// ConfigGeneration is the exact source configuration materialized by the
	// PostgreSQL runtime. It is an internal convergence token and is never copied
	// into evaluator input or logs.
	ConfigGeneration *config.Config
}

func (a *Authorize) EvaluatePostgresSession(ctx context.Context, req PostgresRequest) (*evaluator.Result, error) {
	return a.evaluatePostgres(ctx, req)
}

func (a *Authorize) evaluatePostgres(ctx context.Context, req PostgresRequest) (*evaluator.Result, error) {
	// A configuration writer holds postgresMu while it updates the shared OPA
	// store and builds the evaluator that consumes it. Do not wait behind that
	// writer: sync.RWMutex acquisition is not context-aware, so waiting here can
	// outlive the PostgreSQL server's authorization deadline and delay
	// revocation. TryRLock still permits concurrent evaluations and preserves the
	// writer's active-reader drain, while new requests fail closed as soon as a
	// generation update is pending.
	if !a.postgresMu.TryRLock() {
		return nil, errors.New("postgres authorization configuration is not ready")
	}
	generation := a.postgres
	if !generation.ready || generation.config == nil || generation.state == nil ||
		req.ConfigGeneration == nil || req.ConfigGeneration != generation.config {
		a.postgresMu.RUnlock()
		return nil, errors.New("postgres authorization configuration is not ready")
	}
	ctx = withQuerierForAuthorizeState(ctx, generation.state)

	evalreq := baseEvaluatorRequestFromPostgresRequest(req)
	evalreq.Policy = generation.config.Options.GetRouteForPostgresHostname(req.Hostname)
	if req.RouteRevision != "" {
		if evalreq.Policy == nil {
			a.postgresMu.RUnlock()
			return nil, errors.New("postgres route unavailable during authorization")
		}
		revision, err := evalreq.Policy.PostgresRouteRevision()
		if err != nil {
			a.postgresMu.RUnlock()
			return nil, errors.New("postgres route revision unavailable during authorization")
		}
		if revision != req.RouteRevision {
			a.postgresMu.RUnlock()
			return nil, errors.New("postgres route changed during authorization")
		}
	}
	if evalreq.Policy != nil {
		if routeID, err := evalreq.Policy.RouteID(); err == nil {
			evalreq.Postgres.RouteID = routeID
		}
	}

	res, err := generation.state.evaluator.Evaluate(ctx, evalreq)
	a.postgresMu.RUnlock()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("EvaluatePostgres: error during OPA evaluation")
		return nil, err
	}

	a.fetchSessionAndLogAuthorizeCheck(ctx, zerolog.InfoLevel, req.SessionID, evalreq, res)
	return res, nil
}

func baseEvaluatorRequestFromPostgresRequest(req PostgresRequest) *evaluator.Request {
	validatedProtocolSession := req.ProtocolSession != nil &&
		req.ProtocolSession.IdentityValidated() &&
		req.ProtocolSession.PomeriumSessionID == req.SessionID &&
		req.ProtocolSession.SessionBindingID == req.SessionBindingID &&
		req.ProtocolSession.Hostname == req.Hostname
	sessionID := ""
	if validatedProtocolSession && req.SessionBindingID != "" && req.SessionID != "" {
		sessionID = req.SessionID
	}

	return &evaluator.Request{
		HTTP: evaluator.RequestHTTP{
			Hostname: req.Hostname,
			IP:       req.SourceAddress,
			ClientCertificate: evaluator.ClientCertificateInfo{
				Presented: req.ClientCertPEM != "",
				Leaf:      req.ClientCertPEM,
			},
		},
		Postgres: evaluator.RequestPostgres{
			Hostname:         req.Hostname,
			SessionBindingID: req.SessionBindingID,
			ProtocolSession:  req.ProtocolSession,
		},
		Session: evaluator.RequestSession{
			ID: sessionID,
		},
	}
}
