package graph

import "testing"

func TestTruncateLabel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "no truncation needed",
			input:    "hello",
			maxLen:   10,
			expected: "hello",
		},
		{
			name:     "exact length",
			input:    "hello",
			maxLen:   5,
			expected: "hello",
		},
		{
			name:     "truncation with ellipsis",
			input:    "hello world",
			maxLen:   8,
			expected: "hello...",
		},
		{
			name:     "maxLen equals 3",
			input:    "hello",
			maxLen:   3,
			expected: "hel",
		},
		{
			name:     "maxLen less than 3",
			input:    "hello",
			maxLen:   2,
			expected: "he",
		},
		{
			name:     "empty string",
			input:    "",
			maxLen:   5,
			expected: "",
		},
		{
			name:     "long label truncation",
			input:    "this-is-a-very-long-channel-name",
			maxLen:   22,
			expected: "this-is-a-very-long...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateLabel(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateLabel(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestStateToClass(t *testing.T) {
	tests := []struct {
		state    string
		expected string
	}{
		{"READY", "ready"},
		{"CONNECTING", "connecting"},
		{"IDLE", "idle"},
		{"TRANSIENT_FAILURE", "failure"},
		{"SHUTDOWN", "shutdown"},
		{"UNKNOWN", "neutral"},
		{"", "neutral"},
		{"ready", "neutral"}, // lowercase should not match
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			result := stateToClass(tt.state)
			if result != tt.expected {
				t.Errorf("stateToClass(%q) = %q, want %q", tt.state, result, tt.expected)
			}
		})
	}
}
