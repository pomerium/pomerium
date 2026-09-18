package authenticateflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/agentic"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

// sessionWithClaims builds a run session carrying the act.* claims
// agentic.buildRunSession writes, plus whatever else the caller wants — the
// point being that only the act.-prefixed ones are the executor's identity.
func sessionWithClaims(t *testing.T, claims map[string][]any) *session.Session {
	t.Helper()
	s := &session.Session{}
	s.AddClaims(identity.FlattenedClaims(claims))
	return s
}

func TestAgenticDetails(t *testing.T) {
	t.Parallel()

	sess := sessionWithClaims(t, map[string][]any{
		// Non-act claims belong to the approving human and must not be reported
		// as the workload acting on their behalf.
		"sub":    {"user-1"},
		"email":  {"someone@example.com"},
		"run_id": {"run-1"},
		agentic.ActClaimPrefix + "kubernetes.io.namespace":           {"agentops"},
		agentic.ActClaimPrefix + "kubernetes.io.pod.name":            {"agent-run-7fx2q"},
		agentic.ActClaimPrefix + "kubernetes.io.serviceaccount.name": {"agentops-runner"},
	})

	got := agenticDetails(map[string]string{
		agentic.DetailRunID:                    "run-1",
		agentic.DetailPrompt:                   "review PR #6741",
		agentic.DetailLabelPrefix + "template": "pomerium-zero-claude-code",
		agentic.DetailLabelPrefix + "channel":  "#eng-demos",
		// Pomerium's own detail keys are not labels and must not leak in as ones.
		"client-ip": "192.168.1.1",
	}, sess)

	assert.Equal(t, "run-1", got.RunID)
	assert.Equal(t, "review PR #6741", got.Prompt)
	assert.Equal(t, map[string]string{
		"template": "pomerium-zero-claude-code",
		"channel":  "#eng-demos",
	}, got.Labels)
	assert.Equal(t, map[string]string{
		"kubernetes.io.namespace":           "agentops",
		"kubernetes.io.pod.name":            "agent-run-7fx2q",
		"kubernetes.io.serviceaccount.name": "agentops-runner",
	}, got.WorkloadClaims)
}

func TestAgenticDetails_NoLabelsOrClaims(t *testing.T) {
	t.Parallel()

	// A run created before labels existed, whose session somehow carries no seal.
	got := agenticDetails(map[string]string{agentic.DetailRunID: "run-1"}, &session.Session{})

	assert.Equal(t, "run-1", got.RunID)
	assert.Empty(t, got.Prompt)
	assert.Nil(t, got.Labels)
	assert.Nil(t, got.WorkloadClaims)
}

// TestAgenticResource covers the headline fallback chain. Each step matters: a
// run predating labels, or created by a caller that sets none, still has to name
// itself as something the user can act on rather than render blank.
func TestAgenticResource(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		details *handlers.ProtocolDetailsAgentic
		want    string
	}{
		{
			name: "template label wins",
			details: &handlers.ProtocolDetailsAgentic{
				RunID:  "run-1",
				Labels: map[string]string{"template": "pomerium-zero-claude-code"},
				WorkloadClaims: map[string]string{
					"kubernetes.io.namespace": "agentops",
					"kubernetes.io.pod.name":  "agent-run-7fx2q",
				},
			},
			want: "pomerium-zero-claude-code",
		},
		{
			name: "no template falls back to namespace/pod",
			details: &handlers.ProtocolDetailsAgentic{
				RunID: "run-1",
				WorkloadClaims: map[string]string{
					"kubernetes.io.namespace": "agentops",
					"kubernetes.io.pod.name":  "agent-run-7fx2q",
				},
			},
			want: "agentops/agent-run-7fx2q",
		},
		{
			name: "empty template label is not a template",
			details: &handlers.ProtocolDetailsAgentic{
				RunID:          "run-1",
				Labels:         map[string]string{"template": ""},
				WorkloadClaims: map[string]string{"kubernetes.io.pod.name": "agent-run-7fx2q"},
			},
			want: "agent-run-7fx2q",
		},
		{
			name: "pod without a namespace still names the pod",
			details: &handlers.ProtocolDetailsAgentic{
				RunID:          "run-1",
				WorkloadClaims: map[string]string{"kubernetes.io.pod.name": "agent-run-7fx2q"},
			},
			want: "agent-run-7fx2q",
		},
		{
			name:    "nothing else leaves the run id",
			details: &handlers.ProtocolDetailsAgentic{RunID: "run-1"},
			want:    "run-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, agenticResource(tc.details))
		})
	}
}
