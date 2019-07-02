package authorize

import (
	"testing"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/policy"
)

func TestNew(t *testing.T) {
	t.Parallel()

	policies := testPolicies()

	tests := []struct {
		name      string
		SharedKey string
		Policies  []policy.Policy
		wantErr   bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, false},
		{"bad shared secret", "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==", policies, true},
		{"really bad shared secret", "sup", policies, true},
		{"validation error, short secret", "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==", policies, true},
		{"empty options", "", []policy.Policy{}, true},                                                 // special case
		{"missing policies", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", []policy.Policy{}, false}, // special case
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := config.Options{SharedKey: tt.SharedKey, Policies: tt.Policies}
			if tt.name == "empty options" {
				o = config.Options{}
			}
			_, err := New(o)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("New() = %v, want %v", got, tt.want)
			// }
		})
	}
}

func testPolicies() []policy.Policy {
	testPolicy := policy.Policy{From: "pomerium.io", To: "httpbin.org", AllowedEmails: []string{"test@gmail.com"}}
	testPolicy.Validate()
	policies := []policy.Policy{
		testPolicy,
	}

	return policies
}

func Test_UpdateOptions(t *testing.T) {
	t.Parallel()
	policies := testPolicies()
	newPolicy := policy.Policy{From: "foo.notatld", To: "bar.notatld", AllowedEmails: []string{"test@gmail.com"}}
	newPolicy.Validate()
	newPolicies := []policy.Policy{
		newPolicy,
	}
	identity := &Identity{Email: "test@gmail.com"}
	tests := []struct {
		name        string
		SharedKey   string
		Policies    []policy.Policy
		newPolices  []policy.Policy
		route       string
		wantAllowed bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, policies, "pomerium.io", true},
		{"changed", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, newPolicies, "foo.notatld", true},
		{"changed and missing", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, newPolicies, "pomerium.io", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := config.Options{SharedKey: tt.SharedKey, Policies: tt.Policies}
			authorize, _ := New(o)
			o.Policies = tt.newPolices
			authorize.UpdateOptions(o)

			allowed := authorize.ValidIdentity(tt.route, identity)
			if allowed != tt.wantAllowed {
				t.Errorf("New() allowed = %v, wantAllowed %v", allowed, tt.wantAllowed)
				return
			}
		})
	}
}
