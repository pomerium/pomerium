package config

import (
	"testing"
)

func Test_isValidService(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    bool
	}{
		{"proxy", "proxy", true},
		{"all", "all", true},
		{"authenticate", "authenticate", true},
		{"authenticate bad case", "AuThenticate", false},
		{"authorize implemented", "authorize", true},
		{"jiberish", "xd23", false},
		{"cache", "cache", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidService(tt.service); got != tt.want {
				t.Errorf("isValidService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isAuthenticate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		service string
		want    bool
	}{
		{"proxy", "proxy", false},
		{"all", "all", true},
		{"authenticate", "authenticate", true},
		{"authenticate bad case", "AuThenticate", false},
		{"authorize implemented", "authorize", false},
		{"jiberish", "xd23", false},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthenticate(tt.service); got != tt.want {
				t.Errorf("isAuthenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isAuthorize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		service string
		want    bool
	}{
		{"proxy", "proxy", false},
		{"all", "all", true},
		{"authorize", "authorize", true},
		{"authorize bad case", "AuThorize", false},
		{"authenticate implemented", "authenticate", false},
		{"jiberish", "xd23", false},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			if got := IsAuthorize(tt.service); got != tt.want {
				t.Errorf("isAuthenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
func Test_IsProxy(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    bool
	}{
		{"proxy", "proxy", true},
		{"all", "all", true},
		{"authorize", "authorize", false},
		{"proxy bad case", "PrOxY", false},
		{"jiberish", "xd23", false},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			if got := IsProxy(tt.service); got != tt.want {
				t.Errorf("IsProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_IsCache(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		service string
		want    bool
	}{
		{"proxy", "proxy", false},
		{"all", "all", true},
		{"authorize", "authorize", false},
		{"proxy bad case", "PrOxY", false},
		{"jiberish", "xd23", false},
		{"cache", "cache", true},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			if got := IsCache(tt.service); got != tt.want {
				t.Errorf("IsCache() = %v, want %v", got, tt.want)
			}
		})
	}
}
