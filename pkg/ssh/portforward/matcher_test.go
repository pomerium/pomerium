package portforward

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobMatcher(t *testing.T) {
	tests := []struct {
		inputPattern   string
		generatedRegex string
		isMatchAll     bool
		shouldMatch    []string
		shouldNotMatch []string
	}{
		{"", "^.*$", true, []string{"", "a", "aa", "aaa", "foo"}, []string{}},
		{"*", "^.*$", true, []string{"", "a", "aa", "aaa", "foo"}, []string{}},
		{"**", "^.*$", true, []string{"", "a", "aa", "ab", "aaa"}, []string{}},
		{"localhost", "^.*$", true, []string{"", "a", "aa", "ab", "aaa"}, []string{}},

		{"a", "^a$", false, []string{"a"}, []string{"", "b", "aa"}},
		{"foo", "^foo$", false, []string{"foo"}, []string{" foo", "foo ", "b", "aa"}},
		{"?", "^.$", false, []string{"a", "b"}, []string{"", "aa"}},
		{"a*", "^a.*$", false, []string{"a", "aa", "ab"}, []string{"", "b", "ba"}},
		{"a**", "^a.*$", false, []string{"a", "aa", "ab"}, []string{"", "b", "ba"}},
		{"a***", "^a.*$", false, []string{"a", "aa", "ab"}, []string{"", "b", "ba"}},
		{"?a", "^.a$", false, []string{"aa", "ba"}, []string{"", "ab", "bb"}},
		{"*a", "^.*a$", false, []string{"a", "aa", "ba", "aaaaa", "bbbba"}, []string{"", "ab", "bb"}},
		{"**a", "^.*a$", false, []string{"a", "aa", "ba", "aaaaa", "bbbba"}, []string{"", "ab", "bb"}},
		{"***a", "^.*a$", false, []string{"a", "aa", "ba", "aaaaa", "bbbba"}, []string{"", "ab", "bb"}},
		{"???", "^...$", false, []string{"foo", "bar", "baz"}, []string{"", "a", "aa", "test"}},
		{"*_foo_*", "^.*_foo_.*$", false, []string{"_foo_", "a_foo_b", "_foo_foo_foo_foo_", "_foo_bar"}, []string{"", "foo_bar_"}},
		{`^\.+()|[]{}$`, `^\^\\\.\+\(\)\|\[\]\{\}\$$`, false, []string{`^\.+()|[]{}$`}, []string{}},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			matcher := GlobMatcher(tt.inputPattern)
			require.Equal(t, tt.inputPattern, matcher.InputPattern())
			assert.Equal(t, tt.isMatchAll, matcher.IsMatchAll())
			if tt.isMatchAll {
				assert.Equal(t, tt.generatedRegex, matcher.(*globMatcher).re.String())
			} else {
				assert.Equal(t, fmt.Sprintf("(?i:%s)", tt.generatedRegex), matcher.(*globMatcher).re.String())
			}

			for _, str := range tt.shouldMatch {
				assert.Truef(t, matcher.Match(str), "expected pattern %q to match input %q", tt.inputPattern, str)
				assert.Truef(t, matcher.Match(strings.ToUpper(str)), "expected pattern %q to match input %q (uppercase)", tt.inputPattern, str)
			}
			for _, str := range tt.shouldNotMatch {
				assert.Falsef(t, matcher.Match(str), "expected pattern %q not to match input %q", tt.inputPattern, str)
				assert.Falsef(t, matcher.Match(strings.ToUpper(str)), "expected pattern %q not to match input %q (uppercase)", tt.inputPattern, str)
			}
		})
	}
}

func TestGlobMatcher_EquivalentPatterns(t *testing.T) {
	a := ""
	b := "*"
	c := "**"
	d := "***"
	e := "localhost"
	for _, lhs := range []string{a, b, c, d, e} {
		for _, rhs := range []string{a, b, c, d, e} {
			assert.True(t, GlobMatcher(lhs).Equivalent(rhs))
		}
	}

	assert.True(t, GlobMatcher("foo*").Equivalent("foo*"))
	assert.True(t, GlobMatcher("foo*").Equivalent("foo**"))
	assert.False(t, GlobMatcher("foo*").Equivalent("*foo*"))
	assert.True(t, GlobMatcher("*foo*").Equivalent("**foo*"))
	assert.True(t, GlobMatcher("*foo*").Equivalent("**foo**"))
	assert.True(t, GlobMatcher("foo*bar").Equivalent("foo**bar"))
	assert.True(t, GlobMatcher("foo**bar").Equivalent("foo***bar"))
}

func TestStringMatcher(t *testing.T) {
	{
		matcher := StringMatcher("test")
		assert.Equal(t, "test", matcher.InputPattern())
		assert.False(t, matcher.IsMatchAll())
		assert.True(t, matcher.Match("test"))
		assert.False(t, matcher.Match("not-test"))
	}
	{
		matcher := StringMatcher("")
		assert.Equal(t, "", matcher.InputPattern())
		assert.False(t, matcher.IsMatchAll())
		assert.True(t, matcher.Match(""))
		assert.False(t, matcher.Match("a"))
	}
	{
		matcher := StringMatcher("*")
		assert.Equal(t, "*", matcher.InputPattern())
		assert.False(t, matcher.IsMatchAll())
		assert.False(t, matcher.Match("a"))
		assert.True(t, matcher.Match("*"))
	}
	{
		matcher := StringMatcher("?")
		assert.Equal(t, "?", matcher.InputPattern())
		assert.False(t, matcher.IsMatchAll())
		assert.False(t, matcher.Match("a"))
		assert.True(t, matcher.Match("?"))
	}
}
