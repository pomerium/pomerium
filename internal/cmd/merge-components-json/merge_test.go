package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaxVersion(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected string
	}{
		{
			name:     "single version",
			versions: []string{"v1.0.0"},
			expected: "v1.0.0",
		},
		{
			name:     "pick higher major",
			versions: []string{"v1.0.0", "v2.0.0"},
			expected: "v2.0.0",
		},
		{
			name:     "pick higher minor",
			versions: []string{"v1.1.0", "v1.2.0"},
			expected: "v1.2.0",
		},
		{
			name:     "pick higher patch",
			versions: []string{"v1.0.1", "v1.0.2"},
			expected: "v1.0.2",
		},
		{
			name:     "three versions",
			versions: []string{"v0.9.0", "v0.11.0", "v0.10.0"},
			expected: "v0.11.0",
		},
		{
			name:     "ignore empty strings",
			versions: []string{"", "v1.0.0", ""},
			expected: "v1.0.0",
		},
		{
			name:     "all empty",
			versions: []string{"", "", ""},
			expected: "",
		},
		{
			name:     "mixed with empty",
			versions: []string{"v1.0.0", "", "v2.0.0"},
			expected: "v2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maxVersion(tt.versions...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeComponents(t *testing.T) {
	tests := []struct {
		name     string
		ancestor map[string]string
		ours     map[string]string
		theirs   map[string]string
		expected map[string]string
	}{
		{
			name: "pick highest from each",
			ancestor: map[string]string{
				"config": "v0.10.0",
				"mcp":    "v0.11.0",
				"ssh":    "v0.9.0",
			},
			ours: map[string]string{
				"config": "v0.10.0",
				"mcp":    "v0.12.0",
				"ssh":    "v0.9.0",
			},
			theirs: map[string]string{
				"config": "v0.11.0",
				"mcp":    "v0.11.5",
				"ssh":    "v0.10.0",
			},
			expected: map[string]string{
				"config": "v0.11.0",
				"mcp":    "v0.12.0",
				"ssh":    "v0.10.0",
			},
		},
		{
			name: "new component in ours",
			ancestor: map[string]string{
				"config": "v0.10.0",
			},
			ours: map[string]string{
				"config": "v0.10.0",
				"new":    "v1.0.0",
			},
			theirs: map[string]string{
				"config": "v0.10.0",
			},
			expected: map[string]string{
				"config": "v0.10.0",
				"new":    "v1.0.0",
			},
		},
		{
			name: "new component in theirs",
			ancestor: map[string]string{
				"config": "v0.10.0",
			},
			ours: map[string]string{
				"config": "v0.10.0",
			},
			theirs: map[string]string{
				"config": "v0.10.0",
				"new":    "v1.0.0",
			},
			expected: map[string]string{
				"config": "v0.10.0",
				"new":    "v1.0.0",
			},
		},
		{
			name: "same component added in both with different versions",
			ancestor: map[string]string{
				"config": "v0.10.0",
			},
			ours: map[string]string{
				"config": "v0.10.0",
				"new":    "v1.0.0",
			},
			theirs: map[string]string{
				"config": "v0.10.0",
				"new":    "v2.0.0",
			},
			expected: map[string]string{
				"config": "v0.10.0",
				"new":    "v2.0.0",
			},
		},
		{
			name:     "empty maps",
			ancestor: map[string]string{},
			ours:     map[string]string{},
			theirs:   map[string]string{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeComponents(tt.ancestor, tt.ours, tt.theirs)
			assert.Equal(t, tt.expected, result)
		})
	}
}
