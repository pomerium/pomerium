package authorize

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/log"
)

type PostgresRequest struct {
	Hostname         string
	Database         string
	Username         string
	ApplicationName  string
	StatementClass   string
	QueryProtocol    string
	SessionID        string
	SessionBindingID string
	SourceAddress    string
	ClientCertPEM    string
}

func (a *Authorize) EvaluatePostgresSession(ctx context.Context, req PostgresRequest) (*evaluator.Result, error) {
	return a.evaluatePostgres(ctx, req, zerolog.InfoLevel)
}

func (a *Authorize) EvaluatePostgresQuery(ctx context.Context, req PostgresRequest) (*evaluator.Result, error) {
	return a.evaluatePostgres(ctx, req, zerolog.DebugLevel)
}

func (a *Authorize) evaluatePostgres(ctx context.Context, req PostgresRequest, level zerolog.Level) (*evaluator.Result, error) {
	ctx = a.withQuerierForCheckRequest(ctx)

	evalreq := baseEvaluatorRequestFromPostgresRequest(req)
	evalreq.Policy = a.currentConfig.Load().Options.GetRouteForPostgresHostname(req.Hostname)
	if evalreq.Policy != nil {
		if routeID, err := evalreq.Policy.RouteID(); err == nil {
			evalreq.Postgres.RouteID = routeID
		}
	}

	res, err := a.state.Load().evaluator.Evaluate(ctx, evalreq)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("EvaluatePostgres: error during OPA evaluation")
		return nil, err
	}

	a.fetchSessionAndLogAuthorizeCheck(ctx, level, req.SessionID, evalreq, res)
	return res, nil
}

func baseEvaluatorRequestFromPostgresRequest(req PostgresRequest) *evaluator.Request {
	sessionID := ""
	if req.SessionBindingID != "" && req.SessionID != "" {
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
			Database:         req.Database,
			Username:         req.Username,
			ApplicationName:  req.ApplicationName,
			StatementClass:   req.StatementClass,
			QueryProtocol:    req.QueryProtocol,
			SessionBindingID: req.SessionBindingID,
		},
		Session: evaluator.RequestSession{
			ID: sessionID,
		},
	}
}
