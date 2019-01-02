package options // import "github.com/pomerium/pomerium/internal/options"

import (
	"testing"
)

func TestEmailValidatorValidator(t *testing.T) {
	testCases := []struct {
		name        string
		domains     []string
		email       string
		expectValid bool
	}{
		{
			name:        "nothing should validate when domain list is empty",
			domains:     []string(nil),
			email:       "foo@example.com",
			expectValid: false,
		},
		{
			name:        "single domain validation",
			domains:     []string{"example.com"},
			email:       "foo@example.com",
			expectValid: true,
		},
		{
			name:        "substring matches are rejected",
			domains:     []string{"example.com"},
			email:       "foo@hackerexample.com",
			expectValid: false,
		},
		{
			name:        "no subdomain rollup happens",
			domains:     []string{"example.com"},
			email:       "foo@bar.example.com",
			expectValid: false,
		},
		{
			name:        "multiple domain validation still rejects other domains",
			domains:     []string{"abc.com", "xyz.com"},
			email:       "foo@example.com",
			expectValid: false,
		},
		{
			name:        "multiple domain validation still accepts emails from either domain",
			domains:     []string{"abc.com", "xyz.com"},
			email:       "foo@abc.com",
			expectValid: true,
		},
		{
			name:        "multiple domain validation still rejects other domains",
			domains:     []string{"abc.com", "xyz.com"},
			email:       "bar@xyz.com",
			expectValid: true,
		},
		{
			name:        "comparisons are case insensitive",
			domains:     []string{"Example.Com"},
			email:       "foo@example.com",
			expectValid: true,
		},
		{
			name:        "comparisons are case insensitive",
			domains:     []string{"Example.Com"},
			email:       "foo@EXAMPLE.COM",
			expectValid: true,
		},
		{
			name:        "comparisons are case insensitive",
			domains:     []string{"example.com"},
			email:       "foo@ExAmPlE.CoM",
			expectValid: true,
		},
		{
			name:        "single wildcard allows all",
			domains:     []string{"*"},
			email:       "foo@example.com",
			expectValid: true,
		},
		{
			name:        "single wildcard allows all",
			domains:     []string{"*"},
			email:       "bar@gmail.com",
			expectValid: true,
		},
		{
			name:        "wildcard in list allows all",
			domains:     []string{"example.com", "*"},
			email:       "foo@example.com",
			expectValid: true,
		},
		{
			name:        "wildcard in list allows all",
			domains:     []string{"example.com", "*"},
			email:       "foo@gmail.com",
			expectValid: true,
		},
		{
			name:        "empty email rejected",
			domains:     []string{"example.com"},
			email:       "",
			expectValid: false,
		},
		{
			name:        "wildcard still rejects empty emails",
			domains:     []string{"*"},
			email:       "",
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			emailValidator := NewEmailValidator(tc.domains)
			valid := emailValidator(tc.email)
			if valid != tc.expectValid {
				t.Fatalf("expected %v, got %v", tc.expectValid, valid)
			}
		})
	}
}
