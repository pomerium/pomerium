package authorize

import (
	"testing"

	"github.com/pomerium/pomerium/pkg/config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	policies := testPolicies(t)

	tests := []struct {
		name      string
		SharedKey string
		Policies  []config.Policy
		wantErr   bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, false},
		{"bad shared secret", "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==", policies, true},
		{"really bad shared secret", "sup", policies, true},
		{"validation error, short secret", "AZA85podM73CjLCjViDNz1EUvvejKpWp7Hysr0knXA==", policies, true},
		{"empty options", "", []config.Policy{}, true}, // special case
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
		})
	}
}

func testPolicies(t *testing.T) []config.Policy {
	testPolicy := config.Policy{From: "https://pomerium.io", To: "http://httpbin.org", AllowedEmails: []string{"test@gmail.com"}}
	err := testPolicy.Validate()
	if err != nil {
		t.Fatal(err)
	}
	policies := []config.Policy{
		testPolicy,
	}

	return policies
}

func Test_UpdateOptions(t *testing.T) {
	t.Parallel()
	policies := testPolicies(t)
	newPolicy := config.Policy{From: "https://source.example", To: "http://destination.example", AllowedEmails: []string{"test@gmail.com"}}
	if err := newPolicy.Validate(); err != nil {
		t.Fatal(err)
	}

	newPolicies := []config.Policy{
		newPolicy,
	}
	identity := &Identity{Email: "test@gmail.com"}
	tests := []struct {
		name        string
		SharedKey   string
		Policies    []config.Policy
		newPolices  []config.Policy
		route       string
		wantAllowed bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, policies, "pomerium.io", true},
		{"changed", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, newPolicies, "source.example", true},
		{"changed and missing", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, newPolicies, "pomerium.io", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := config.Options{SharedKey: tt.SharedKey, Policies: tt.Policies}
			authorize, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			o.Policies = tt.newPolices
			if err := authorize.UpdateOptions(o); err != nil {
				t.Fatal(err)
			}

			allowed := authorize.ValidIdentity(tt.route, identity)
			if allowed != tt.wantAllowed {
				t.Errorf("New() allowed = %v, wantAllowed %v", allowed, tt.wantAllowed)
				return
			}
		})
	}

	// Test nil
	var a *Authorize
	a.UpdateOptions(config.Options{})
}
