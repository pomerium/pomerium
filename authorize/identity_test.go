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
			i := &Identity{Email: tt.Email}
			if got := i.EmailDomain(); got != tt.want {
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
		want     bool
	}{
		{"valid domain", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "user@example.com"}, true},
		{"invalid domain prepend", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "a@1example.com"}, false},
		{"invalid domain postpend", []policy.Policy{{From: "example.com", AllowedDomains: []string{"example.com"}}}, "example.com", &Identity{Email: "user@example.com2"}, false},
		{"valid group", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"admin"}}, true},
		{"invalid group", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"everyone"}}, false},
		{"invalid empty", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{""}}, false},
		{"valid group multiple", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"everyone", "admin"}}, true},
		{"invalid group multiple", []policy.Policy{{From: "example.com", AllowedGroups: []string{"admin"}}}, "example.com", &Identity{Email: "user@example.com", Groups: []string{"everyones", "sadmin"}}, false},
		{"valid user email", []policy.Policy{{From: "example.com", AllowedEmails: []string{"user@example.com"}}}, "example.com", &Identity{Email: "user@example.com"}, true},
		{"invalid user email", []policy.Policy{{From: "example.com", AllowedEmails: []string{"user@example.com"}}}, "example.com", &Identity{Email: "user2@example.com"}, false},
		{"empty everything", []policy.Policy{{From: "example.com"}}, "example.com", &Identity{Email: "user2@example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl := NewIdentityWhitelist(tt.policies)
			if got := wl.Valid(tt.route, tt.Identity); got != tt.want {
				t.Errorf("IdentityACLMap.Allowed() = %v, want %v", got, tt.want)
			}

		})
	}
}
