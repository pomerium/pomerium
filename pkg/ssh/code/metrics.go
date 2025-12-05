package code

import (
	"context"

	otelattribute "go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func linearBuckets(numBuckets int, maximum float64) []float64 {
	if numBuckets <= 0 || maximum <= 0 {
		return nil
	}
	buckets := make([]float64, numBuckets)
	step := maximum / float64(numBuckets)
	for i := range numBuckets {
		buckets[i] = step * float64(i+1)
	}
	return buckets
}

type Metrics struct {
	// SSHAuthCodeRequestsTotal tracks the total number of times an authentication request comes into the ssh endpoint
	SSHAuthCodeRequestsTotal metric.Int64Counter
	// SSHAuthCodeRequestsTotal counts the total number of ssh clients connected and awaiting authentication
	// this can be for three main reasons
	// - internal : an internal bug or unexpected behaviour
	// - user-revoked : user denied the code
	// - timeout : user failed to authenticate within the timeout, or cancelled the request
	SSHAuthCodeRequestFailuresTotal metric.Int64Counter
	// SSHActivePendingSessions counts the total number of ssh clients connected and awaiting authentication
	SSHActivePendingSessions metric.Int64Counter
	// SSHIssueCodeDuration measures the duration it takes to associated a unique code to a request in the ssh authorization code flow
	SSHIssueCodeDuration metric.Float64Histogram
	// SSHUserCodeDecisionDuration measures the duration from the time the code is issued to when it is accepted or denied
	SSHUserCodeDecisionDuration metric.Float64Histogram
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	codeReqTotal, err := meter.Int64Counter(
		"ssh.auth.code.requests.total",
		metric.WithDescription("tracks the total number of times an authentication request comes into the ssh endpoint"),
	)
	if err != nil {
		return nil, err
	}
	codeRequestFailuresTotal, err := meter.Int64Counter(
		"ssh.auth.code.requests.failures.total",
		metric.WithDescription("tracks the total number of failures to authenticate a code request."),
	)
	if err != nil {
		return nil, err
	}

	activePendingSessions, err := meter.Int64Counter(
		"ssh.auth.code.pending.sessions.count",
		metric.WithDescription("counts the total number of ssh clients connected and awaiting authentication"),
	)
	if err != nil {
		return nil, err
	}
	issueCodeDuration, err := meter.Float64Histogram(
		"ssh.auth.code.issue.duration",
		metric.WithUnit("s"),
		metric.WithDescription("measures the duration it takes to associated a unique code to a request in the ssh authorization code flow"),
	)
	if err != nil {
		return nil, err
	}

	userCodeDecision, err := meter.Float64Histogram(
		"ssh.auth.code.user.decision",
		metric.WithDescription("measures the duration from the time the code is issued to when it is accepted or denied"),
		metric.WithExplicitBucketBoundaries(
			linearBuckets(10, DefaultCodeTTL.Seconds())...,
		),
	)
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

func (m *Metrics) PendingSessionInc(ctx context.Context) {
	m.SSHActivePendingSessions.Add(ctx, 1)
}

func (m *Metrics) PendingSessionDec(ctx context.Context) {
	m.SSHActivePendingSessions.Add(ctx, -1)
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
