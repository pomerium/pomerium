package authenticate

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func Test_validRedirectURI(t *testing.T) {

	tests := []struct {
		name        string
		uri         string
		rootDomains []string
		want        bool
	}{
		{"good url redirect", "https://example.com/redirect", []string{"example.com"}, true},
		{"bad domain", "https://example.com/redirect", []string{"notexample.com"}, false},
		{"malformed url", "^example.com/redirect", []string{"notexample.com"}, false},
		{"empty domain list", "https://example.com/redirect", []string{}, false},
		{"empty domain", "https://example.com/redirect", []string{""}, false},
		{"empty url", "", []string{"example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validRedirectURI(tt.uri, tt.rootDomains); got != tt.want {
				t.Errorf("validRedirectURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validSignature(t *testing.T) {
	goodUrl := "https://example.com/redirect"
	secretA := "41aOD7VNtQ1/KZDCGrkYpaHwB50JC1y6BDs2KPRVd2A="
	now := fmt.Sprint(time.Now().Unix())
	rawSig := redirectURLSignature(goodUrl, time.Now(), secretA)
	sig := base64.URLEncoding.EncodeToString(rawSig)
	staleTime := fmt.Sprint(time.Now().Add(-6 * time.Minute).Unix())

	tests := []struct {
		name        string
		redirectURI string
		sigVal      string
		timestamp   string
		secret      string
		want        bool
	}{
		{"good signature", goodUrl, string(sig), now, secretA, true},
		{"empty redirect url", "", string(sig), now, secretA, false},
		{"bad redirect url", "https://google.com^", string(sig), now, secretA, false},
		{"malformed signature", goodUrl, string(sig + "^"), now, "&*&@**($&#(", false},
		{"malformed timestamp", goodUrl, string(sig), now + "^", secretA, false},
		{"stale timestamp", goodUrl, string(sig), staleTime, secretA, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validSignature(tt.redirectURI, tt.sigVal, tt.timestamp, tt.secret); got != tt.want {
				t.Errorf("validSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_redirectURLSignature(t *testing.T) {
	tests := []struct {
		name        string
		rawRedirect string
		timestamp   time.Time
		secret      string
		want        string
	}{
		{"good signature", "https://example.com/redirect", time.Unix(1546797901, 0), "41aOD7VNtQ1/KZDCGrkYpaHwB50JC1y6BDs2KPRVd2A=", "GIDyWKjrG_7MwXwIq1o51f2pDT_rH9aLHdsHxSBEwy8="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redirectURLSignature(tt.rawRedirect, tt.timestamp, tt.secret)
			out := base64.URLEncoding.EncodeToString(got)
			if out != tt.want {
				t.Errorf("redirectURLSignature() = %v, want %v", tt.want, out)
			}
		})
	}
}
