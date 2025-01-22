package portal

import (
	"strings"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type matcher[T any] func(left T, right parser.Value) bool

var stringMatchers = map[string]matcher[string]{
	"contains":    matchStringContains,
	"ends_with":   matchStringEndsWith,
	"is":          matchStringIs,
	"starts_with": matchStringStartsWith,
}

var stringListMatchers = map[string]matcher[[]string]{
	"has": matchStringListHas,
	"is":  matchStringListIs,
}

func matchString(left string, right parser.Value) bool {
	obj, ok := right.(parser.Object)
	if !ok {
		obj = parser.Object{
			"is": right,
		}
	}

	for k, v := range obj {
		f, ok := stringMatchers[k]
		if !ok {
			return false
		}
		ok = f(left, v)
		if ok {
			return true
		}
	}
	return false
}

func matchStringContains(left string, right parser.Value) bool {
	str, ok := right.(parser.String)
	if !ok {
		return false
	}
	return strings.Contains(left, string(str))
}

func matchStringEndsWith(left string, right parser.Value) bool {
	str, ok := right.(parser.String)
	if !ok {
		return false
	}
	return strings.HasSuffix(left, string(str))
}

func matchStringIs(left string, right parser.Value) bool {
	str, ok := right.(parser.String)
	if !ok {
		return false
	}
	return left == string(str)
}

func matchStringStartsWith(left string, right parser.Value) bool {
	str, ok := right.(parser.String)
	if !ok {
		return false
	}
	return strings.HasPrefix(left, string(str))
}

func matchStringList(left []string, right parser.Value) bool {
	obj, ok := right.(parser.Object)
	if !ok {
		obj = parser.Object{
			"has": right,
		}
	}

	for k, v := range obj {
		f, ok := stringListMatchers[k]
		if !ok {
			return false
		}
		ok = f(left, v)
		if ok {
			return true
		}
	}
	return false
}

func matchStringListHas(left []string, right parser.Value) bool {
	for _, str := range left {
		if matchStringIs(str, right) {
			return true
		}
	}
	return false
}

func matchStringListIs(left []string, right parser.Value) bool {
	return len(left) == 1 && matchStringListHas(left, right)
}
