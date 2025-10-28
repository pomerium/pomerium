package portforward

import (
	"regexp"
	"strings"
)

type Matcher interface {
	InputPattern() string
	IsMatchAll() bool
	Match(str string) bool
	Equivalent(pattern string) bool
}

// globMatcher is a limited glob matcher supporting only ? and * wildcards,
// compatible with openssh match_pattern().
type globMatcher struct {
	inputPattern string // the exact pattern that was compiled
	re           *regexp.Regexp
}

var regexMatchAll = regexp.MustCompile("^.*$")

func isMatchAllPattern(pattern string) bool {
	// Openssh will send the empty string if the client requests either the
	// empty string or a single '*'.
	//
	// 'localhost' is special: it's the default when using the syntax
	// '-R port:host:hostport'. Compared to '-R :port:host:hostport' (with the
	// extra colon) which sends empty string. We treat it the same for pattern
	// matching purposes, and we could look for it in the future to trigger
	// specific behavior when using that syntax.
	return pattern == "" || strings.Trim(pattern, "*") == "" || pattern == "localhost"
}

func globToRegex(pattern string) string {
	regexPattern := make([]byte, 0, 2*len(pattern)+2)
	// note: openssh patterns are case-insensitive
	regexPattern = append(regexPattern, "(?i:^"...)
	for i := 0; i < len(pattern); i++ {
		switch b := pattern[i]; b {
		case '*':
			for i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
			}
			regexPattern = append(regexPattern, ".*"...)
		case '?':
			regexPattern = append(regexPattern, '.')
		case '\\', '.', '+', '(', ')', '|', '[', ']', '{', '}', '^', '$':
			regexPattern = append(regexPattern, '\\', b)
		default:
			// non-escape character
			regexPattern = append(regexPattern, b)
		}
	}
	regexPattern = append(regexPattern, "$)"...)
	return string(regexPattern)
}

func GlobMatcher(pattern string) Matcher {
	if isMatchAllPattern(pattern) {
		return &globMatcher{
			inputPattern: pattern,
			re:           regexMatchAll,
		}
	}

	return &globMatcher{
		inputPattern: pattern,
		re:           regexp.MustCompile(globToRegex(pattern)),
	}
}

func (g *globMatcher) InputPattern() string {
	return g.inputPattern
}

func (g *globMatcher) IsMatchAll() bool {
	return (g.re == regexMatchAll)
}

func (g *globMatcher) Match(str string) bool {
	return g.re.MatchString(str)
}

func (g *globMatcher) Equivalent(pattern string) bool {
	return g.inputPattern == pattern || // "foo*" == "foo*"
		g.IsMatchAll() && isMatchAllPattern(pattern) || // "*" == "**" == ""
		g.re.String() == globToRegex(pattern) // "foo*bar" == "foo**bar"
}

type stringMatcher struct {
	inputPattern string // the exact pattern that was compiled
}

func StringMatcher(str string) Matcher {
	return &stringMatcher{inputPattern: str}
}

func (g *stringMatcher) InputPattern() string {
	return g.inputPattern
}

func (g *stringMatcher) IsMatchAll() bool {
	return false
}

func (g *stringMatcher) Match(str string) bool {
	return g.inputPattern == str
}

func (g *stringMatcher) Equivalent(pattern string) bool {
	return g.inputPattern == pattern
}
