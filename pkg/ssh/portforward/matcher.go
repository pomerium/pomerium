package portforward

import (
	"regexp"
	"strings"
)

// Matcher is a limited glob matcher supporting only ? and * wildcards,
// compatible with openssh match_pattern().
type Matcher struct {
	inputPattern string // the exact pattern that was compiled
	re           *regexp.Regexp
}

var regexMatchAll = regexp.MustCompile("^.*$")

func CompileMatcher(pattern string) Matcher {
	// Openssh will send the empty string if the client requests either the
	// empty string or a single '*'.
	//
	// 'localhost' is special: it's the default when using the syntax
	// '-R port:host:hostport'. Compared to '-R :port:host:hostport' (with the
	// extra colon) which sends empty string. We treat it the same for pattern
	// matching purposes, and we could look for it in the future to trigger
	// specific behavior when using that syntax.
	if pattern == "" || strings.Trim(pattern, "*") == "" || pattern == "localhost" {
		return Matcher{
			inputPattern: pattern,
			re:           regexMatchAll,
		}
	}

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
	return Matcher{
		inputPattern: pattern,
		re:           regexp.MustCompile(string(regexPattern)),
	}
}

func (g *Matcher) InputPattern() string {
	return g.inputPattern
}

func (g *Matcher) IsMatchAll() bool {
	return (g.re == regexMatchAll)
}

func (g *Matcher) Match(str string) bool {
	return g.re.MatchString(str)
}
