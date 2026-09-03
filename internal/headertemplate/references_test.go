package headertemplate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/headertemplate"
)

func TestReferences(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		in     string
		expect [][]string
	}{
		{name: "single secret", in: "Bearer ${secret.a}", expect: [][]string{{"secret", "a"}}},
		{name: "mixed in order", in: "u=$pomerium.user x=${secret.b}", expect: [][]string{{"pomerium", "user"}, {"secret", "b"}}},
		{name: "simple form", in: "$secret.a", expect: [][]string{{"secret", "a"}}},
		{name: "escape yields none", in: "$$secret.a", expect: nil},
		{name: "repeated appears twice", in: "${secret.a}${secret.a}", expect: [][]string{{"secret", "a"}, {"secret", "a"}}},
		{name: "bracket form", in: `${secret["weird id"]}`, expect: [][]string{{"secret", "weird id"}}},
		{name: "plain text", in: "no refs here", expect: nil},
		{name: "malformed nesting reports inner only", in: "${secret.${pomerium.x}}", expect: [][]string{{"pomerium", "x"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expect, headertemplate.References(tc.in))
		})
	}
}
