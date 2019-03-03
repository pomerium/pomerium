package authorize // import "github.com/pomerium/pomerium/authorize"

import (
	"fmt"
	"strings"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/policy"
)

// Identity contains a user's identity information.
type Identity struct {
	User   string
	Email  string
	Groups []string
}

// EmailDomain returns the domain of the identity's email.
func (i *Identity) EmailDomain() string {
	if i.Email == "" {
		return ""
	}
	comp := strings.Split(i.Email, "@")
	if len(comp) != 2 || comp[0] == "" {
		return ""
	}
	return comp[1]
}

// IdentityValidator provides an interface to check whether a user has access
// to a given route.
type IdentityValidator interface {
	Valid(string, *Identity) bool
}

type identityWhitelist struct {
	sync.RWMutex
	m map[string]bool
}

// newIdentityWhitelistMap takes a slice of policies and creates a hashmap of identity
// authorizations per-route for each allowed group, domain, and email.
func newIdentityWhitelistMap(policies []policy.Policy) *identityWhitelist {
	var im identityWhitelist
	im.m = make(map[string]bool, len(policies)*3)
	for _, p := range policies {
		for _, group := range p.AllowedGroups {
			log.Debug().Str("route", p.From).Str("group", group).Msg("add group")
			im.PutGroup(p.From, group)
		}
		for _, domain := range p.AllowedDomains {
			im.PutDomain(p.From, domain)
			log.Debug().Str("route", p.From).Str("group", domain).Msg("add domain")

		}
		for _, email := range p.AllowedEmails {
			im.PutEmail(p.From, email)
			log.Debug().Str("route", p.From).Str("group", email).Msg("add email")
		}
	}
	return &im
}

// Valid reports whether an identity has valid access for a given route.
func (m *identityWhitelist) Valid(route string, i *Identity) bool {
	if ok := m.Domain(route, i.EmailDomain()); ok {
		return ok
	}
	if ok := m.Email(route, i.Email); ok {
		return ok
	}
	for _, group := range i.Groups {
		if ok := m.Group(route, group); ok {
			return ok
		}
	}
	return false
}

// Group retrieves per-route access given a group name.
func (m *identityWhitelist) Group(route, group string) bool {
	m.RLock()
	defer m.RUnlock()
	return m.m[fmt.Sprintf("%s|group:%s", route, group)]
}

// PutGroup adds an access entry for a route given a group name.
func (m *identityWhitelist) PutGroup(route, group string) {
	m.Lock()
	m.m[fmt.Sprintf("%s|group:%s", route, group)] = true
	m.Unlock()
}

// Domain retrieves per-route access given a domain name.
func (m *identityWhitelist) Domain(route, domain string) bool {
	m.RLock()
	defer m.RUnlock()
	return m.m[fmt.Sprintf("%s|domain:%s", route, domain)]
}

// PutDomain adds an access entry for a route given a domain name.
func (m *identityWhitelist) PutDomain(route, domain string) {
	m.Lock()
	m.m[fmt.Sprintf("%s|domain:%s", route, domain)] = true
	m.Unlock()
}

// Email retrieves per-route access given a user's email.
func (m *identityWhitelist) Email(route, email string) bool {
	m.RLock()
	defer m.RUnlock()
	return m.m[fmt.Sprintf("%s|email:%s", route, email)]
}

// PutEmail adds an access entry for a route given a user's email.
func (m *identityWhitelist) PutEmail(route, email string) {
	m.Lock()
	m.m[fmt.Sprintf("%s|email:%s", route, email)] = true
	m.Unlock()
}

// MockIdentityValidator is a mock implementation of IdentityValidator
type MockIdentityValidator struct{ ValidResponse bool }

// Valid  is a mock implementation IdentityValidator's Valid method
func (mv *MockIdentityValidator) Valid(u string, i *Identity) bool { return mv.ValidResponse }
