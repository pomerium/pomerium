package agentic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

func TestBindingDisplayDetails(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		run  *oauth21proto.AgenticRun
		want map[string]string
	}{
		{
			name: "labels are namespaced under the label prefix",
			run: &oauth21proto.AgenticRun{
				Id:     "run-1",
				Prompt: "review PR #6741",
				Labels: map[string]string{
					"template": "pomerium-zero-claude-code",
					"channel":  "#eng-demos",
				},
			},
			want: map[string]string{
				"run_id":         "run-1",
				"prompt":         "review PR #6741",
				"label.template": "pomerium-zero-claude-code",
				"label.channel":  "#eng-demos",
			},
		},
		{
			name: "a run with no labels or prompt carries only its id",
			run:  &oauth21proto.AgenticRun{Id: "run-1"},
			want: map[string]string{"run_id": "run-1"},
		},
		{
			name: "a whitespace-only prompt is not recorded",
			run:  &oauth21proto.AgenticRun{Id: "run-1", Prompt: "   \n  "},
			want: map[string]string{"run_id": "run-1"},
		},
		{
			// A caller naming a label "client-ip" must not be able to overwrite the
			// detail key Pomerium sets itself.
			name: "a label cannot collide with Pomerium's own detail keys",
			run: &oauth21proto.AgenticRun{
				Id:     "run-1",
				Labels: map[string]string{"client-ip": "10.0.0.1", "run_id": "spoofed"},
			},
			want: map[string]string{
				"run_id":          "run-1",
				"label.client-ip": "10.0.0.1",
				"label.run_id":    "spoofed",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, bindingDisplayDetails(tc.run))
		})
	}
}

// TestBindingDisplayDetails_PromptVerbatim pins that the whole prompt is carried
// onto the binding: the page truncates it for display and shows the full text on
// hover, which it can only do if the full text is there.
func TestBindingDisplayDetails_PromptVerbatim(t *testing.T) {
	t.Parallel()

	prompt := strings.Repeat("a", maxPromptBytes)
	got := bindingDisplayDetails(&oauth21proto.AgenticRun{Id: "run-1", Prompt: prompt})
	assert.Equal(t, prompt, got["prompt"])
}

func TestValidateLabels(t *testing.T) {
	t.Parallel()

	t.Run("no labels is fine", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validateLabels(nil))
		require.NoError(t, validateLabels(map[string]string{}))
	})

	t.Run("at the limits", func(t *testing.T) {
		t.Parallel()
		labels := map[string]string{}
		for i := range maxLabels {
			labels[string(rune('a'+i))] = ""
		}
		require.NoError(t, validateLabels(labels))
		require.NoError(t, validateLabels(map[string]string{
			strings.Repeat("k", maxLabelKeyBytes): strings.Repeat("v", maxLabelValueBytes),
		}))
	})

	for _, tc := range []struct {
		name   string
		labels map[string]string
		errMsg string
	}{
		{
			name: "too many",
			labels: func() map[string]string {
				m := map[string]string{}
				for i := range maxLabels + 1 {
					m[string(rune('a'+i))] = "v"
				}
				return m
			}(),
			errMsg: "at most",
		},
		{
			name:   "empty key",
			labels: map[string]string{"": "v"},
			errMsg: "non-empty",
		},
		{
			name:   "key too long",
			labels: map[string]string{strings.Repeat("k", maxLabelKeyBytes+1): "v"},
			errMsg: "label keys must be at most",
		},
		{
			name:   "value too long",
			labels: map[string]string{"k": strings.Repeat("v", maxLabelValueBytes+1)},
			errMsg: "label values must be at most",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateLabels(tc.labels)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}
