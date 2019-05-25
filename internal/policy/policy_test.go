package policy

import (
	"net/url"
	"reflect"
	"testing"
)

func Test_urlParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		uri     string
		want    *url.URL
		wantErr bool
	}{
		{"good url without schema", "accounts.google.com", &url.URL{Scheme: "https", Host: "accounts.google.com"}, false},
		{"good url with schema", "https://accounts.google.com", &url.URL{Scheme: "https", Host: "accounts.google.com"}, false},
		{"bad url, malformed", "https://accounts.google.^", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := urlParse(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("urlParse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("urlParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Validate(t *testing.T) {
	t.Parallel()
	basePolicy := Policy{From: "httpbin.corp.example", To: "httpbin.corp.notatld"}

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
		{"cors policy", corsPolicy, false},
		{"public policy", publicPolicy, false},
		{"public and whitelist", publicAndWhitelistPolicy, true},
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
