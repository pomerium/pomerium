package options // import "github.com/pomerium/pomerium/internal/options"

import (
	"fmt"
	"strings"
)

// NewEmailValidator returns a function that checks whether a given email is valid based on a list
// of domains. The domain "*" is a wild card that matches any non-empty email.
func NewEmailValidator(domains []string) func(string) bool {
	allowAll := false
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
		}
		domains[i] = fmt.Sprintf("@%s", strings.ToLower(domain))
	}

	if allowAll {
		return func(email string) bool { return email != "" }
	}

	return func(email string) bool {
		if email == "" {
			return false
		}
		email = strings.ToLower(email)
		for _, domain := range domains {
			if strings.HasSuffix(email, domain) {
				return true
			}
		}
		return false
	}
}
