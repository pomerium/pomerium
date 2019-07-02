package authorize

import (
	"testing"

	"github.com/pomerium/pomerium/internal/policy"
)

func TestIdentity_EmailDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		Email string
		want  string
	}{
		{"simple", "user@pomerium.io", "pomerium.io"},
		{"period malformed", "user@.io", ".io"},
		{"empty", "", ""},
		{"empty first part", "@uhoh.com", ""},
		{"empty second part", "uhoh@", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EmailDomain(tt.Email); got != tt.want {
				t.Errorf("Identity.EmailDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_IdentityWhitelistMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		policies []policy.Policy
		route    string
		Identity *Identity
		admins   []string
		want     bool
	}{
		{"valid domain", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "user@example.com"}, nil, true},
		{"valid domain with admins", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "user@example.com"}, []string{"admin@example.com"}, true},
		{"invalid domain prepend", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "a@1example.com"}, nil, false},
		{"invalid domain postpend", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "user@example.com2"}, nil, false},
		{"valid group", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"admin"}}, nil, true},
		{"invalid group", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"everyone"}}, nil, false},
		{"invalid empty", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{""}}, nil, false},
		{"valid group multiple", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"everyone", "admin"}}, nil, true},
		{"invalid group multiple", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"everyones", "sadmin"}}, nil, false},
		{"valid user email", []policy.Policy{{From: "example.com", AllowedEmails: []string{"user@example.com"}}}, "example.com", &Identity{Email: "user@example.com"}, nil, true},
		{"invalid user email", []policy.Policy{{From: "example.com", AllowedEmails: []string{"user@example.com"}}}, "example.com", &Identity{Email: "user2@example.com"}, nil, false},
		{"empty everything", []policy.Policy{{From: "example.com"}}, "example.com", &Identity{Email: "user2@example.com"}, nil, false},
		{"empty policy", []policy.Policy{}, "example.com", &Identity{Email: "user@example.com"}, nil, false},
		// impersonation related
		{"admin not impersonating allowed", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "admin@example.com"}, []string{"admin@example.com"}, true},
		{"admin not impersonating denied", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "admin@admin-domain.com"}, []string{"admin@admin-domain.com"}, false},
		{"impersonating match domain", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@example.com"}, []string{"admin@admin-domain.com"}, true},
		{"impersonating does not match domain", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@not-example.com"}, []string{"admin@admin-domain.com"}, false},
		{"impersonating match email", []policy.Policy{{From: "example.com", AllowedEmails: []string{"user@example.com"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@example.com"}, []string{"admin@admin-domain.com"}, true},
		{"impersonating does not match email", []policy.Policy{{From: "example.com", AllowedEmails: []string{"user@example.com"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@not-example.com"}, []string{"admin@admin-domain.com"}, false},
		{"impersonating match groups", []policy.Policy{{From: "example.com", AllowedGroups: []string{"support"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"support"}}, []string{"admin@admin-domain.com"}, true},
		{"impersonating match many groups", []policy.Policy{{From: "example.com", AllowedGroups: []string{"support"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"a", "b", "c", "support"}}, []string{"admin@admin-domain.com"}, true},
		{"impersonating does not match groups", []policy.Policy{{From: "example.com", AllowedGroups: []string{"support"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"not support"}}, []string{"admin@admin-domain.com"}, false},
		{"impersonating does not match many groups", []policy.Policy{{From: "example.com", AllowedGroups: []string{"support"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"not support", "b", "c"}}, []string{"admin@admin-domain.com"}, false},
		{"impersonating does not match empty groups", []policy.Policy{{From: "example.com", AllowedGroups: []string{"support"}}}, "example.com", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{""}}, []string{"admin@admin-domain.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl := NewIdentityWhitelist(tt.policies, tt.admins)
			if got := wl.Valid(tt.route, tt.Identity); got != tt.want {
				t.Errorf("wl.Valid() = %v, want %v", got, tt.want)
			}

		})
	}
}
