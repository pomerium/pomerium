package portal

import (
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// User is the computed user information needed for access decisions.
type User struct {
	SessionID string
	UserID    string
	Email     string
	Groups    []string
}

// CheckRouteAccess checks if the user has access to the route.
func CheckRouteAccess(user User, route *config.Policy) bool {
	// check the main policy
	ppl := route.ToPPL()
	if checkPPLAccess(user, ppl) {
		return true
	}

	// check sub-policies
	for _, sp := range route.SubPolicies {
		if sp.SourcePPL == "" {
			continue
		}

		ppl, err := parser.New().ParseYAML(strings.NewReader(sp.SourcePPL))
		if err != nil {
			// ignore invalid PPL
			continue
		}

		if checkPPLAccess(user, ppl) {
			return true
		}
	}

	// nothing matched
	return false
}

func checkPPLAccess(user User, ppl *parser.Policy) bool {
	for _, r := range ppl.Rules {
		// ignore deny rules
		if r.Action != parser.ActionAllow {
			continue
		}

		// ignore complex rules
		if len(r.Nor) > 0 || len(r.Not) > 0 || len(r.And) > 1 {
			continue
		}

		cs := append(append([]parser.Criterion{}, r.Or...), r.And...)
		for _, c := range cs {
			ok := checkPPLCriterionAccess(user, c)
			if ok {
				return true
			}
		}
	}

	return false
}

func checkPPLCriterionAccess(user User, criterion parser.Criterion) bool {
	switch criterion.Name {
	case "accept":
		return true
	}

	// require a session
	if user.SessionID == "" {
		return false
	}

	switch criterion.Name {
	case "authenticated_user":
		return true
	}

	// require a user
	if user.UserID == "" {
		return false
	}

	switch criterion.Name {
	case "domain":
		parts := strings.SplitN(user.Email, "@", 2)
		return len(parts) == 2 && matchString(parts[1], criterion.Data)
	case "email":
		return matchString(user.Email, criterion.Data)
	case "groups":
		return matchStringList(user.Groups, criterion.Data)
	case "user":
		return matchString(user.UserID, criterion.Data)
	}

	return false
}
