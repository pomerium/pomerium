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
		{"authorize implemented", "authorize", true},
		{"jiberish", "xd23", false},
		{"databroker", "databroker", true},
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

func Test_IsDataBroker(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		service string
		want    bool
	}{
		{"proxy", "proxy", false},
		{"all", "all", true},
		{"authorize", "authorize", false},
		{"jiberish", "xd23", false},
		{"cache", "cache", true},
		{"databroker", "databroker", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDataBroker(tt.service); got != tt.want {
				t.Errorf("IsDataBroker() = %v, want %v", got, tt.want)
			}
		})
	}
}
