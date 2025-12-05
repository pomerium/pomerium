package code

import (
	"context"

	otelattribute "go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type Metrics struct {
	// SSHAuthCodeRequestsTotal tracks the total number of times an authentication
	// request comes into the ssh endpoint
	SSHAuthCodeRequestsTotal metric.Int64Counter
	// SSHAuthCodeRequestsTotal tracks the total number of failures to authenticate
	// a code request.
	// this can be for three main reasons
	// - internal : an internal bug or unexpected behaviour
	// - user-revoked : user denied the code
	// - timeout : user failed to authenticate within the timeout, or cancelled the request
	SSHAuthCodeRequestFailuresTotal metric.Int64Counter
	// SSHActivePendingSessions counts the total number of ssh clients connected and awaiting authentication
	SSHActivePendingSessions metric.Int64Counter
	// SSHIssueCodeDuration measures the duration it takes to query / get / create a unique code
	// for authorization code flow
	SSHIssueCodeDuration metric.Float64Histogram
	// SSHUserCodeDecisionDuration measures the duration it takes for an end-user to go through the stateful flow
	// and make a decision about the code (success/failure) from the time the user is prompted with the code.
	SSHUserCodeDecisionDuration metric.Float64Histogram
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	codeReqTotal, err := meter.Int64Counter("ssh.auth.code.requests.total")
	if err != nil {
		return nil, err
	}
	codeRequestFailuresTotal, err := meter.Int64Counter("ssh.auth.code.failures.total")
	if err != nil {
		return nil, err
	}

	activePendingSessions, err := meter.Int64Counter("ssh.auth.code.pending.sessions.count")
	if err != nil {
		return nil, err
	}
	issueCodeDuration, err := meter.Float64Histogram("ssh.auth.issue.code.duration", metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}

	userCodeDecision, err := meter.Float64Histogram("ssh.auth.code.user.decision")
	if err != nil {
		return nil, err
	}
	return &Metrics{
		SSHAuthCodeRequestsTotal:        codeReqTotal,
		SSHAuthCodeRequestFailuresTotal: codeRequestFailuresTotal,
		SSHActivePendingSessions:        activePendingSessions,
		SSHIssueCodeDuration:            issueCodeDuration,
		SSHUserCodeDecisionDuration:     userCodeDecision,
	}, nil
}

func (m *Metrics) PendingSessionInc() {
	m.SSHActivePendingSessions.Add(context.TODO(), 1)
}

func (m *Metrics) PendingSessionDec() {
	m.SSHActivePendingSessions.Add(context.TODO(), -1)
}

type Failure string

const (
	FailureTimeout  Failure = "timeout"
	FailureInternal Failure = "internal"
	FailureRevoked  Failure = "user-revoked"
)

func FailureReason(
	reason Failure,
) otelattribute.KeyValue {
	return otelattribute.String("failure", string(reason))
}
