package authorize

import (
	"testing"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/policy"
)

func TestNew(t *testing.T) {
	t.Parallel()

	goodPolicy := policy.Policy{From: "pomerium.io", To: "httpbin.org"}
	goodPolicy.Validate()
	policies := []policy.Policy{
		goodPolicy,
	}

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
		{"nil options", "", []policy.Policy{}, true},                                                  // special case
		{"missing policies", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", []policy.Policy{}, true}, // special case
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &config.Options{SharedKey: tt.SharedKey, Policies: tt.Policies}
			if tt.name == "nil options" {
				o = nil
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
