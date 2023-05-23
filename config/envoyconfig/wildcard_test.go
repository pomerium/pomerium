package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSpecialWildcardHost(t *testing.T) {
	cases := []struct {
		host     string
		expected bool
	}{
		{"", false},
		{"*", false},
		{"a*", false},
		{"ab", false},
		{"*b", false},
		{"abc", false},
		{"*.foo.example.com", false},
		{"*-bar.example.com", false},
		{"foo.*", false},
		{"foo-*", false},
		{"foo.*.bar.example.com", true},
		{"foo.bar-*.example.com", true},
		{"a*b", true},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.host, func(t *testing.T) {
			actual := isSpecialWildcardHost(c.host)
			assert.Equal(t, c.expected, actual)
		})
	}
}
