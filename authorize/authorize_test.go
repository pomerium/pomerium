package authorize

import (
	"testing"

	"github.com/pomerium/pomerium/config"
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
			o := config.Options{
				AuthenticateURL: mustParseURL("https://authN.example.com"),
				SharedKey:       tt.SharedKey,
				Policies:        tt.Policies}
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
	testPolicy := config.Policy{From: "https://pomerium.io", To: "http://httpbin.org", AllowedUsers: []string{"test@gmail.com"}}
	err := testPolicy.Validate()
	if err != nil {
		t.Fatal(err)
	}
	policies := []config.Policy{
		testPolicy,
	}
	return policies
}
