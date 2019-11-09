package authorize // import "github.com/pomerium/pomerium/authorize"

import (
	"fmt"
	"strings"
	"sync"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

// Identity contains a user's identity information.
type Identity struct {
	User   string
	Email  string
	Groups []string
	// Impersonation
	ImpersonateEmail  string
	ImpersonateGroups []string
}

// IsImpersonating returns whether the user is trying to impersonate another
// user email or group.
func (i *Identity) IsImpersonating() bool {
	if i.ImpersonateEmail != "" || len(i.ImpersonateGroups) != 0 {
		return true
	}
	return false
}

// EmailDomain returns the domain portion of an email.
func EmailDomain(email string) string {
	if email == "" {
		return ""
	}
	comp := strings.Split(email, "@")
	if len(comp) != 2 || comp[0] == "" {
		return ""
	}
	return comp[1]
}

// IdentityValidator provides an interface to check whether a user has access
// to a given route.
type IdentityValidator interface {
	Valid(string, *Identity) bool
	IsAdmin(*Identity) bool
}

type whitelist struct {
	sync.RWMutex
	access map[string]bool
	admins map[string]bool
}

// newIdentityWhitelistMap takes a slice of policies and creates a hashmap of identity
// authorizations per-route for each allowed group, domain, and email.
func newIdentityWhitelistMap(policies []config.Policy, admins []string) *whitelist {
	if len(policies) == 0 {
		log.Warn().Msg("authorize: loaded configuration with no policies")
	}
	var wl whitelist
	wl.access = make(map[string]bool, len(policies)*3)
	for _, p := range policies {
		for _, group := range p.AllowedGroups {
			wl.PutGroup(p.Source.Host, group)
			log.Debug().Str("route", p.Source.Host).Str("group", group).Msg("add group")
		}
		for _, domain := range p.AllowedDomains {
			wl.PutDomain(p.Source.Host, domain)
			log.Debug().Str("route", p.Source.Host).Str("domain", domain).Msg("add domain")
		}
		for _, email := range p.AllowedEmails {
			wl.PutEmail(p.Source.Host, email)
			log.Debug().Str("route", p.Source.Host).Str("email", email).Msg("add email")
		}
	}

	wl.admins = make(map[string]bool, len(admins))
	for _, admin := range admins {
		wl.PutAdmin(admin)
		log.Debug().Str("admin", admin).Msg("add administrator")
	}
	return &wl
}

// Valid reports whether an identity has valid access for a given route.
func (wl *whitelist) Valid(route string, i *Identity) bool {
	email := i.Email
	domain := EmailDomain(email)
	groups := i.Groups

	// if user is admin, and wants to impersonate, override values
	if wl.IsAdmin(i) && i.IsImpersonating() {
		email = i.ImpersonateEmail
		domain = EmailDomain(email)
		groups = i.ImpersonateGroups
	}

	if ok := wl.Email(route, email); ok {
		return ok
	}
	if ok := wl.Domain(route, domain); ok {
		return ok
	}
	for _, group := range groups {
		if ok := wl.Group(route, group); ok {
			return ok
		}
	}
	return false
}

func (wl *whitelist) IsAdmin(i *Identity) bool {
	if ok := wl.Admin(i.Email); ok {
		return ok
	}
	return false
}

// Group retrieves per-route access given a group name.
func (wl *whitelist) Group(route, group string) bool {
	wl.RLock()
	defer wl.RUnlock()
	return wl.access[fmt.Sprintf("%s|group:%s", route, group)]
}

// PutGroup adds an access entry for a route given a group name.
func (wl *whitelist) PutGroup(route, group string) {
	wl.Lock()
	wl.access[fmt.Sprintf("%s|group:%s", route, group)] = true
	wl.Unlock()
}

// Domain retrieves per-route access given a domain name.
func (wl *whitelist) Domain(route, domain string) bool {
	wl.RLock()
	defer wl.RUnlock()
	return wl.access[fmt.Sprintf("%s|domain:%s", route, domain)]
}

// PutDomain adds an access entry for a route given a domain name.
func (wl *whitelist) PutDomain(route, domain string) {
	wl.Lock()
	wl.access[fmt.Sprintf("%s|domain:%s", route, domain)] = true
	wl.Unlock()
}

// Email retrieves per-route access given a user's email.
func (wl *whitelist) Email(route, email string) bool {
	wl.RLock()
	defer wl.RUnlock()
	return wl.access[fmt.Sprintf("%s|email:%s", route, email)]
}

// PutEmail adds an access entry for a route given a user's email.
func (wl *whitelist) PutEmail(route, email string) {
	wl.Lock()
	wl.access[fmt.Sprintf("%s|email:%s", route, email)] = true
	wl.Unlock()
}

// PutEmail adds an admin entry
func (wl *whitelist) PutAdmin(admin string) {
	wl.Lock()
	wl.admins[admin] = true
	wl.Unlock()
}

// Admin checks if the email matches an admin
func (wl *whitelist) Admin(admin string) bool {
	wl.RLock()
	defer wl.RUnlock()
	return wl.admins[admin]
}

// MockIdentityValidator is a mock implementation of IdentityValidator
type MockIdentityValidator struct {
	ValidResponse   bool
	IsAdminResponse bool
}

// Valid is a mock implementation IdentityValidator's Valid method
func (mv *MockIdentityValidator) Valid(u string, i *Identity) bool { return mv.ValidResponse }

// IsAdmin is a mock implementation IdentityValidator's IsAdmin method
func (mv *MockIdentityValidator) IsAdmin(i *Identity) bool { return mv.IsAdminResponse }
