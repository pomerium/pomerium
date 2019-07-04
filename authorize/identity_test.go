package authorize

import (
	"testing"

	"github.com/pomerium/pomerium/internal/config"
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
		policies []config.Policy
		route    string
		Identity *Identity
		admins   []string
		want     bool
	}{
		{"valid domain", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, nil, true},
		{"valid domain with admins", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, []string{"admin@example.com"}, true},
		{"invalid domain prepend", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "a@1example.com"}, nil, false},
		{"invalid domain postpend", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com2"}, nil, false},
		{"valid group", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"admin"}}, nil, true},
		{"invalid group", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"everyone"}}, nil, false},
		{"invalid empty", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{""}}, nil, false},
		{"valid group multiple", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"everyone", "admin"}}, nil, true},
		{"invalid group multiple", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"everyones", "sadmin"}}, nil, false},
		{"valid user email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedEmails: []string{"user@example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, nil, true},
		{"invalid user email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedEmails: []string{"user@example.com"}}}, "from.example", &Identity{Email: "user2@example.com"}, nil, false},
		{"empty everything", []config.Policy{{From: "https://from.example", To: "https://to.example"}}, "from.example", &Identity{Email: "user2@example.com"}, nil, false},
		{"empty policy", []config.Policy{}, "from.example", &Identity{Email: "user2@example.com"}, nil, false},
		// impersonation related
		{"admin not impersonating allowed", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@example.com"}, []string{"admin@example.com"}, true},
		{"admin not impersonating denied", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com"}, []string{"admin@admin-domain.com"}, false},
		{"impersonating match domain", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@example.com"}, []string{"admin@admin-domain.com"}, true},
		{"impersonating does not match domain", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@not-example.com"}, []string{"admin@admin-domain.com"}, false},
		{"impersonating match email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedEmails: []string{"user@example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@example.com"}, []string{"admin@admin-domain.com"}, true},
		{"impersonating does not match email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedEmails: []string{"user@example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@not-example.com"}, []string{"admin@admin-domain.com"}, false},
		{"impersonating match groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"support"}}, []string{"admin@admin-domain.com"}, true},
		{"impersonating match many groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"a", "b", "c", "support"}}, []string{"admin@admin-domain.com"}, true},
		{"impersonating does not match groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"not support"}}, []string{"admin@admin-domain.com"}, false},
		{"impersonating does not match many groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"not support", "b", "c"}}, []string{"admin@admin-domain.com"}, false},
		{"impersonating does not match empty groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{""}}, []string{"admin@admin-domain.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.policies {
				if err := (&tt.policies[i]).Validate(); err != nil {
					t.Fatal(err)
				}
			}

			wl := NewIdentityWhitelist(tt.policies, tt.admins)
			if got := wl.Valid(tt.route, tt.Identity); got != tt.want {
				t.Errorf("wl.Valid() = %v, want %v", got, tt.want)
			}

		})
	}
}
