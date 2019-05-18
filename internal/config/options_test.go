package config

import (
	"os"
	"reflect"
	"testing"
)

func Test_optionsFromEnvConfig(t *testing.T) {
	good := NewOptions()
	good.SharedKey = "test"
	tests := []struct {
		name     string
		want     *Options
		envKey   string
		envValue string
		wantErr  bool
	}{
		{"good default with no env settings", good, "", "", false},
		{"invalid service type", nil, "SERVICES", "invalid", true},
		{"good service", good, "SERVICES", "all", false},
		{"bad debug boolean", nil, "POMERIUM_DEBUG", "yes", true},
		{"missing shared secret", nil, "SHARED_SECRET", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			if tt.envKey != "" {
				os.Setenv(tt.envKey, tt.envValue)
			}
			if tt.envKey != "SHARED_SECRET" {
				os.Setenv("SHARED_SECRET", "test")
			}
			got, err := OptionsFromEnvConfig()
			os.Unsetenv(tt.envKey)

			if (err != nil) != tt.wantErr {
				t.Errorf("optionsFromEnvConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("optionsFromEnvConfig() = got %#v,\n want %#v", got, tt.want)
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
		{"authorize implemented", "authorize", true},
		{"jiberish", "xd23", false},
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
