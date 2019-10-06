package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import "strings"

// ParentSubdomain returns the parent subdomain.
func ParentSubdomain(s string) string {
	if strings.Count(s, ".") < 2 {
		return ""
	}
	split := strings.SplitN(s, ".", 2)
	return split[1]
}
