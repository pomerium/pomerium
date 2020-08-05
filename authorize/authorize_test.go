package authorize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := &config.Options{
				AuthenticateURL: mustParseURL("https://authN.example.com"),
				DataBrokerURL:   mustParseURL("https://cache.example.com"),
				SharedKey:       tt.SharedKey,
				Policies:        tt.Policies}
			if tt.name == "empty options" {
				o = &config.Options{}
			}
			_, err := New(o)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAuthorize_OnConfigChange(t *testing.T) {
	t.Parallel()
	policies := testPolicies(t)
	tests := []struct {
		name           string
		SharedKey      string
		Policies       []config.Policy
		expectedChange bool
	}{
		{"good", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, true},
		{"bad option", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", policies, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := &config.Options{
				AuthenticateURL: mustParseURL("https://authN.example.com"),
				DataBrokerURL:   mustParseURL("https://cache.example.com"),
				SharedKey:       tc.SharedKey,
				Policies:        tc.Policies,
			}
			a, err := New(o)
			require.NoError(t, err)
			require.NotNil(t, a)

			oldPe := a.pe
			cfg := &config.Config{Options: o}
			assertFunc := assert.True
			o.SigningKey = "bad-share-key"
			if tc.expectedChange {
				o.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUhHNHZDWlJxUFgwNGtmSFQxeVVDM1pUQkF6MFRYWkNtZ043clpDcFE3cHJvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFbzQzdjAwQlR4c3pKZWpmdHhBOWNtVGVUSmtQQXVtOGt1b0UwVlRUZnlId2k3SHJlN2FRUgpHQVJ6Nm0wMjVRdGFiRGxqeDd5MjIyY1gxblhCQXo3MlF3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
				assertFunc = assert.False
			}
			a.OnConfigChange(cfg)
			assertFunc(t, oldPe == a.pe)
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
