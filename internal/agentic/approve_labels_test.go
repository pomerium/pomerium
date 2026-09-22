package agentic

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
)

// TestConsentPageRendersLabels pins that the consent page discloses the run's
// labels. They are the run's context — which workflow, which channel — and are
// often the only thing distinguishing two identical prompts, so approving
// without seeing them is approving blind.
func TestConsentPageRendersLabels(t *testing.T) {
	t.Parallel()

	run := &agenticpb.Run{
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

	t.Run("the page data carries every label", func(t *testing.T) {
		data := consentPageData{
			Prompt: run.GetPrompt(),
			Labels: runLabels(run),
		}.toJSON()

		assert.Equal(t, run.GetPrompt(), data["prompt"], "the prompt is still shown")
		labels, _ := data["labels"].([]runLabel)
		require.Len(t, labels, len(run.GetLabels()))
		got := map[string]string{}
		for _, l := range labels {
			got[l.Key] = l.Value
		}
		assert.Equal(t, run.GetLabels(), got, "every label must be disclosed")
	})

	t.Run("a run with no labels carries an empty list", func(t *testing.T) {
		data := consentPageData{Prompt: "x"}.toJSON()
		assert.Empty(t, data["labels"])
	})
}
