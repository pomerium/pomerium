package main

import (
	"os"
	"reflect"
	"testing"
)

func init() {
	os.Clearenv()
}
func Test_optionsFromEnvConfig(t *testing.T) {
	tests := []struct {
		name     string
		want     *Options
		envKey   string
		envValue string
		wantErr  bool
	}{
		{"good default with no env settings", defaultOptions, "", "", false},
		{"good service", defaultOptions, "SERVICES", "all", false},
		{"bad debug boolean", nil, "POMERIUM_DEBUG", "yes", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envKey != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}
			got, err := optionsFromEnvConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("optionsFromEnvConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("optionsFromEnvConfig() = got %v, want %v", got, tt.want)
			}
		})
	}
}

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
		{"authorize not yet implemented", "authorize", false},
		{"jiberish", "xd23", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidService(tt.service); got != tt.want {
				t.Errorf("isValidService() = %v, want %v", got, tt.want)
			}
		})
	}
}
