package config // import "github.com/pomerium/pomerium/internal/config"

import (
	"testing"
)

func Test_Validate(t *testing.T) {
	t.Parallel()
	basePolicy := Policy{From: "https://httpbin.corp.example", To: "https://httpbin.corp.notatld"}

	corsPolicy := basePolicy
	corsPolicy.CORSAllowPreflight = true

	publicPolicy := basePolicy
	publicPolicy.AllowPublicUnauthenticatedAccess = true

	publicAndWhitelistPolicy := publicPolicy
	publicAndWhitelistPolicy.AllowedEmails = []string{"test@gmail.com"}

	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{"good", basePolicy, false},
		{"empty to host", Policy{From: "https://httpbin.corp.example", To: "https://"}, true},
		{"empty from host", Policy{From: "https://", To: "https://httpbin.corp.example"}, true},
		{"empty from scheme", Policy{From: "httpbin.corp.example", To: "https://httpbin.corp.example"}, true},
		{"empty to scheme", Policy{From: "https://httpbin.corp.example", To: "//httpbin.corp.example"}, true},
		{"cors policy", corsPolicy, false},
		{"public policy", publicPolicy, false},
		{"public and whitelist", publicAndWhitelistPolicy, true},
		{"route must have", publicAndWhitelistPolicy, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
