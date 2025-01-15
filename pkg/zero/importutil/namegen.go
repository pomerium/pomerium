package importutil

import (
	"crypto/x509"
	"fmt"
	"iter"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cespare/xxhash/v2"
)

func GenerateCertName(cert *x509.Certificate) *string {
	var out string
	if cert.IsCA {
		if cert.Subject.CommonName != "" {
			out = cert.Subject.CommonName
		} else {
			out = cert.Subject.String()
		}
	} else {
		if cert.Subject.CommonName != "" {
			out = cert.Subject.CommonName
		} else if len(cert.DNSNames) > 0 {
			out = pickDNSName(cert.DNSNames)
		} else {
			out = "leaf"
		}
	}

	if strings.Contains(out, "-") {
		out = strings.ReplaceAll(out, " ", "_")
	} else {
		out = strings.ReplaceAll(out, " ", "-")
	}

	suffix := fmt.Sprintf("@%d", cert.NotBefore.Unix())
	if !strings.Contains(out, suffix) {
		out += suffix
	}

	return &out
}

func pickDNSName(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	// prefer wildcard names
	for _, name := range names {
		if strings.HasPrefix(name, "*.") {
			return name
		}
	}
	return names[0]
}

type Route interface {
	comparable
	GetFrom() string
	GetPrefix() string
	GetPath() string
	GetRegex() string
}

func GenerateRouteNames[T Route](routes []T) []string {
	out := make([]string, len(routes))
	prefixes := make([][]string, len(routes))
	indexes := map[T]int{}
	trie := newDomainTrie[T]()
	for i, route := range routes {
		trie.Insert(route)
		indexes[route] = i
	}
	trie.Compact()

	trie.Walk(func(parents []string, node *domainTreeNode[T]) {
		for subdomain, child := range node.children {
			for route, name := range differentiateRoutes(subdomain, child.routes) {
				idx := indexes[route]
				out[idx] = name
				prefixes[idx] = parents
			}
		}
	})

	seen := map[string]int{}
	for idx, name := range out {
		prevIdx, ok := seen[name]
		if !ok {
			out[idx] = name
			seen[name] = idx
			continue
		}
		delete(seen, name)
		var b strings.Builder
		b.WriteString(name)
		var prevNameB strings.Builder
		prevNameB.WriteString(out[prevIdx])
		var nameB strings.Builder
		nameB.WriteString(name)
		minLen := min(len(prefixes[prevIdx]), len(prefixes[idx]))
		maxLen := max(len(prefixes[prevIdx]), len(prefixes[idx]))
		for j := range maxLen {
			if j >= minLen {
				if j < len(prefixes[prevIdx]) {
					prevNameB.WriteRune('-')
					prevNameB.WriteString(strings.ReplaceAll(prefixes[prevIdx][j], ".", "-"))
				} else {
					nameB.WriteRune('-')
					nameB.WriteString(strings.ReplaceAll(prefixes[idx][j], ".", "-"))
				}
				continue
			}
			prevPrefix, prefix := trimCommonSubdomains(prefixes[prevIdx][j], prefixes[idx][j])
			if prevPrefix != prefix {
				prevNameB.WriteRune('-')
				prevNameB.WriteString(prevPrefix)
				nameB.WriteRune('-')
				nameB.WriteString(prefix)
			}
		}

		out[prevIdx] = prevNameB.String()
		out[idx] = nameB.String()
		seen[out[prevIdx]] = prevIdx
		seen[out[idx]] = idx
	}

	for i, name := range out {
		if name == "" {
			out[i] = fmt.Sprintf("route-%d", i)
		}
	}
	return out
}

func trimCommonSubdomains(a, b string) (string, string) {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for len(aParts) > 1 && len(bParts) > 1 && aParts[0] == bParts[0] {
		aParts = aParts[1:]
		bParts = bParts[1:]
	}
	for len(aParts) > 1 && len(bParts) > 1 && aParts[len(aParts)-1] == bParts[len(bParts)-1] {
		aParts = aParts[:len(aParts)-1]
		bParts = bParts[:len(bParts)-1]
	}
	return strings.Join(aParts, "-"), strings.Join(bParts, "-")
}

func differentiateRoutes[T Route](subdomain string, routes []T) iter.Seq2[T, string] {
	return func(yield func(T, string) bool) {
		if len(routes) == 1 {
			yield(routes[0], subdomain)
			return
		}
		names := map[string][]T{}
		replacer := strings.NewReplacer(
			" ", "_",
			"/", "-",
			"*", "",
		)
		simplePathName := func(pathOrPrefix string) string {
			if p, err := url.PathUnescape(pathOrPrefix); err == nil {
				pathOrPrefix = strings.ToLower(p)
			}
			return replacer.Replace(strings.Trim(pathOrPrefix, "/ "))
		}
		genericRegexCounter := 0
		regexName := func(regex string) string {
			if path, pattern, ok := commonRegexPattern(regex); ok {
				name := simplePathName(path)
				if name == "" && pattern != "" {
					return "re-any"
				}
				return fmt.Sprintf("re-%s-prefix", name)
			}
			genericRegexCounter++
			return fmt.Sprintf("re-%d", genericRegexCounter)
		}
		var prefixCount, pathCount int
		for _, route := range routes {
			// each route will have the same domain, but a unique prefix/path/regex.
			var name string
			switch {
			case route.GetPrefix() != "":
				name = simplePathName(route.GetPrefix())
				prefixCount++
			case route.GetPath() != "":
				name = simplePathName(route.GetPath())
				pathCount++
			case route.GetRegex() != "":
				name = regexName(route.GetRegex())
			}
			names[name] = append(names[name], route)
		}

		nameCounts := map[uint64]int{}
		for name, routes := range names {
			if len(routes) == 1 {
				var b strings.Builder
				b.WriteString(subdomain)
				if name != "" {
					b.WriteRune('-')
					b.WriteString(name)
				}
				if !yield(routes[0], b.String()) {
					return
				}
			} else {
				// assign a "-prefix" or "-path" suffix to routes with the same name
				// but different configurations
				prefixSuffix := "-prefix"
				pathSuffix := "-path"
				switch {
				case prefixCount == 1 && pathCount == 1:
					pathSuffix = ""
				case prefixCount > 1 && pathCount == 1:
					prefixSuffix = ""
				case prefixCount == 1 && pathCount > 1:
					pathSuffix = ""
				case prefixCount == 0:
					pathSuffix = ""
				case pathCount == 0:
					prefixSuffix = ""
				}
				var b strings.Builder
				for _, route := range routes {
					b.Reset()
					b.WriteString(subdomain)
					if name != "" {
						b.WriteRune('-')
						b.WriteString(name)
					}
					if route.GetPrefix() != "" {
						b.WriteString(prefixSuffix)
					} else if route.GetPath() != "" {
						b.WriteString(pathSuffix)
					}

					sum := xxhash.Sum64String(b.String())
					nameCounts[sum]++
					if c := nameCounts[sum]; c > 1 {
						b.WriteString(" (")
						b.WriteString(strconv.Itoa(c))
						b.WriteString(")")
					}
					if !yield(route, b.String()) {
						return
					}
				}
			}
		}
	}
}

type domainTreeNode[T Route] struct {
	parent   *domainTreeNode[T]
	children map[string]*domainTreeNode[T]
	routes   []T
}

func (n *domainTreeNode[T]) insert(key string, route T) *domainTreeNode[T] {
	if existing, ok := n.children[key]; ok {
		var def T
		if route != def {
			existing.routes = append(existing.routes, route)
		}
		return existing
	}
	node := &domainTreeNode[T]{
		parent:   n,
		children: map[string]*domainTreeNode[T]{},
	}
	var def T
	if route != def {
		node.routes = append(node.routes, route)
	}
	n.children[key] = node
	return node
}

type domainTrie[T Route] struct {
	root *domainTreeNode[T]
}

func newDomainTrie[T Route]() *domainTrie[T] {
	t := &domainTrie[T]{
		root: &domainTreeNode[T]{
			children: map[string]*domainTreeNode[T]{},
		},
	}
	return t
}

func (t *domainTrie[T]) Walk(fn func(parents []string, node *domainTreeNode[T])) {
	t.root.walk(nil, fn)
}

func (n *domainTreeNode[T]) walk(prefix []string, fn func(parents []string, node *domainTreeNode[T])) {
	for key, child := range n.children {
		fn(append(prefix, key), child)
		child.walk(append(prefix, key), fn)
	}
}

func (t *domainTrie[T]) Insert(route T) {
	u, _ := url.Parse(route.GetFrom())
	if u == nil {
		// ignore invalid urls, they will be assigned generic fallback names
		return
	}
	parts := strings.Split(u.Hostname(), ".")
	slices.Reverse(parts)
	cur := t.root
	for _, part := range parts[:len(parts)-1] {
		var def T
		cur = cur.insert(part, def)
	}
	cur.insert(parts[len(parts)-1], route)
}

func (t *domainTrie[T]) Compact() {
	t.root.compact()
}

func (n *domainTreeNode[T]) compact() {
	for _, child := range n.children {
		child.compact()
	}
	if n.parent == nil {
		return
	}
	var firstKey string
	var firstChild *domainTreeNode[T]
	for key, child := range n.children {
		firstKey, firstChild = key, child
		break
	}
	// compact intermediate nodes, not leaves
	if len(n.children) == 1 && len(firstChild.routes) == 0 {
		firstChild.parent = n.parent
		for key, child := range n.parent.children {
			if child == n {
				delete(n.parent.children, key)
				n.parent.children[fmt.Sprintf("%s.%s", key, firstKey)] = firstChild
				*n = domainTreeNode[T]{}
				break
			}
		}
	}
}

// Matches an optional leading slash, then zero or more path segments separated
// by '/' characters, where the final path segment contains one of the following
// commonly used regex patterns used to match path segments:
// - '.*' or '.+'
// - '[^/]*', '[^/]+', '[^\/]*', or '[^\/]+'
// - '\w*' or '\w+'
// - any of the above patterns, enclosed by parentheses
// The first capture group contains the path leading up to the wildcard segment
// and can be empty or have leading/trailing slashes. The second capture group
// contains the wildcard segment with no leading or trailing slashes.
var pathPrefixMatchRegex = regexp.MustCompile(`^(\/?(?:\w+\/)*)(\(?(?:\.\+|\.\*|\[\^\\?\/\][\+\*]|\\w[\+\*])\)?)$`)

func commonRegexPattern(re string) (path string, pattern string, found bool) {
	re = strings.TrimSuffix(strings.TrimPrefix(re, "^"), "$")
	if match := pathPrefixMatchRegex.FindStringSubmatch(re); match != nil {
		return match[1], match[2], true
	}
	return "", "", false
}
