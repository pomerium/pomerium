package agentic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// TestConsentPageRendersLabels pins that the consent page discloses the run's
// labels. They are the run's context — which workflow, which channel — and are
// often the only thing distinguishing two identical prompts, so approving
// without seeing them is approving blind.
func TestConsentPageRendersLabels(t *testing.T) {
	t.Parallel()

	run := &oauth21proto.AgenticRun{
		Id:     "run-1",
		Prompt: "triage the backlog",
		Labels: map[string]string{
			"workflow": "nightly-triage",
			"channel":  "C0123456789",
		},
	}

	t.Run("labels are sorted, not caller-ordered", func(t *testing.T) {
		got := runLabels(run)
		require.Len(t, got, 2)
		assert.Equal(t, "channel", got[0].Key)
		assert.Equal(t, "workflow", got[1].Key)
	})

	t.Run("the rendered page shows every label", func(t *testing.T) {
		var sb strings.Builder
		require.NoError(t, consentPage.Execute(&sb, consentPageData{
			Prompt: run.GetPrompt(),
			Labels: runLabels(run),
		}))
		page := sb.String()

		assert.Contains(t, page, run.GetPrompt(), "the prompt is still shown")
		for k, v := range run.GetLabels() {
			assert.Contains(t, page, k, "label key %q must be disclosed", k)
			assert.Contains(t, page, v, "label value %q must be disclosed", v)
		}
	})

	t.Run("a run with no labels renders nothing extra", func(t *testing.T) {
		var sb strings.Builder
		require.NoError(t, consentPage.Execute(&sb, consentPageData{Prompt: "x"}))
		assert.NotContains(t, sb.String(), "<dl>")
	})
}
