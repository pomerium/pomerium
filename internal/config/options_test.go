package config

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/pomerium/pomerium/internal/policy"
	"github.com/spf13/viper"
)

func Test_validate(t *testing.T) {

	testOptions := func() *Options {
		o := NewOptions()
		o.SharedKey = "test"
		o.Services = "all"
		return o
	}
	good := testOptions()
	badServices := testOptions()
	badServices.Services = "blue"
	badSecret := testOptions()
	badSecret.SharedKey = ""
	badRoutes := testOptions()
	badRoutes.Routes = map[string]string{"foo": "bar"}
	badPolicyFile := testOptions()
	badPolicyFile.PolicyFile = "file"

	tests := []struct {
		name     string
		testOpts *Options
		wantErr  bool
	}{
		{"good default with no env settings", good, false},
		{"invalid service type", badServices, true},
		{"missing shared secret", badSecret, true},
		{"routes present", badRoutes, true},
		{"policy file specified", badPolicyFile, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testOpts.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("optionsFromEnvConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
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

func Test_isAuthorize(t *testing.T) {
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
func Test_bindEnvs(t *testing.T) {
	o := &Options{}
	os.Clearenv()
	defer os.Unsetenv("POMERIUM_DEBUG")
	defer os.Unsetenv("POLICY")
	os.Setenv("POMERIUM_DEBUG", "true")
	os.Setenv("POLICY", "mypolicy")
	o.bindEnvs()
	err := viper.Unmarshal(o)
	if err != nil {
		t.Errorf("Could not unmarshal %#v: %s", o, err)
	}
	if !o.Debug {
		t.Errorf("Failed to load POMERIUM_DEBUG from environment")
	}
	if o.Services != "" {
		t.Errorf("Somehow got SERVICES from environment without configuring it")
	}
	if o.PolicyEnv != "mypolicy" {
		t.Errorf("Failed to bind policy env var to PolicyEnv")
	}
}

func Test_parseURLs(t *testing.T) {
	tests := []struct {
		name            string
		authorizeURL    string
		authenticateURL string
		wantErr         bool
	}{
		{"good", "https://authz.mydomain.tld", "https://authn.mydomain.tld", false},
		{"bad authorize", "notaurl", "https://authn.mydomain.tld", true},
		{"bad authenticate", "https://authz.mydomain.tld", "notaurl", true},
		{"only authn", "", "https://authn.mydomain.tld", false},
		{"only authz", "https://authz.mydomain.tld", "", false},
	}
	for _, test := range tests {
		o := &Options{
			AuthenticateURLString: test.authenticateURL,
			AuthorizeURLString:    test.authorizeURL,
		}
		err := o.parseURLs()
		if !test.wantErr && err != nil {
			t.Errorf("Failed to parse URLs %v: %s", test, err)
		}
		if o.AuthenticateURL.String() != test.authenticateURL {
			t.Errorf("Failed to update AuthenticateURL: %v", test)
		}
		if o.AuthorizeURL.String() != test.authorizeURL {
			t.Errorf("Failed to update AuthorizeURL: %v", test)
		}
	}

}

func Test_OptionsFromViper(t *testing.T) {
	testPolicy := policy.Policy{
		To:   "https://httpbin.org",
		From: "https://pomerium.io",
	}
	testPolicy.Validate()
	testPolicies := []policy.Policy{
		testPolicy,
	}

	goodConfigBytes := []byte(`{"shared_secret":"Setec Astronomy","service":"all","policy":[{"from":"https://pomerium.io","to":"https://httpbin.org"}]}`)
	goodOptions := NewOptions()
	goodOptions.SharedKey = "Setec Astronomy"
	goodOptions.Services = "all"
	goodOptions.Policies = testPolicies
	goodOptions.CookieName = "oatmeal"

	badConfigBytes := []byte("badjson!")
	badUnmarshalConfigBytes := []byte(`"debug": "blue"`)

	tests := []struct {
		name        string
		configBytes []byte
		want        *Options
		wantErr     bool
	}{
		{"good", goodConfigBytes, goodOptions, false},
		{"bad json", badConfigBytes, nil, true},
		{"bad unmarshal", badUnmarshalConfigBytes, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			os.Clearenv()
			os.Setenv("COOKIE_NAME", "oatmeal")
			defer os.Unsetenv("COOKIE_NAME")
			tempFile, _ := ioutil.TempFile("", "*.json")
			defer tempFile.Close()
			defer os.Remove(tempFile.Name())
			tempFile.Write(tt.configBytes)
			got, err := OptionsFromViper(tempFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("OptionsFromViper() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OptionsFromViper() = %v, want %v", got, tt.want)
			}

		})
	}

	// Test for missing config file
	o, err := OptionsFromViper("filedoesnotexist")
	if o != nil || err == nil {
		t.Errorf("OptionsFromViper(): Did when loading missing file")
	}
}

func Test_parsePolicyEnv(t *testing.T) {
	t.Parallel()
	source := "https://pomerium.io"
	sourceURL, _ := url.ParseRequestURI(source)
	dest := "https://httpbin.org"
	destURL, _ := url.ParseRequestURI(dest)

	tests := []struct {
		name        string
		policyBytes []byte
		want        []policy.Policy
		wantErr     bool
	}{
		{"simple json", []byte(fmt.Sprintf(`[{"from": "%s","to":"%s"}]`, source, dest)), []policy.Policy{{From: source, To: dest, Source: sourceURL, Destination: destURL}}, false},
		{"bad from", []byte(`[{"from": "%","to":"httpbin.org"}]`), nil, true},
		{"bad to", []byte(`[{"from": "pomerium.io","to":"%"}]`), nil, true},
		{"simple error", []byte(`{}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := new(Options)

			o.PolicyEnv = base64.StdEncoding.EncodeToString(tt.policyBytes)
			err := o.parsePolicy()
			if (err != nil) != tt.wantErr {
				t.Errorf("parasePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(o.Policies, tt.want) {
				t.Errorf("parasePolicy() = \n%v, want \n%v", o, tt.want)
			}
		})
	}

	// Catch bad base64
	o := new(Options)
	o.PolicyEnv = "foo"
	err := o.parsePolicy()
	if err == nil {
		t.Errorf("parasePolicy() did not catch bad base64 %v", o)
	}
}

func Test_parsePolicyFile(t *testing.T) {
	source := "https://pomerium.io"
	sourceURL, _ := url.ParseRequestURI(source)
	dest := "https://httpbin.org"
	destURL, _ := url.ParseRequestURI(dest)

	tests := []struct {
		name        string
		policyBytes []byte
		want        []policy.Policy
		wantErr     bool
	}{
		{"simple json", []byte(fmt.Sprintf(`{"policy":[{"from": "%s","to":"%s"}]}`, source, dest)), []policy.Policy{{From: source, To: dest, Source: sourceURL, Destination: destURL}}, false},
		{"bad from", []byte(`{"policy":[{"from": "%","to":"httpbin.org"}]}`), nil, true},
		{"bad to", []byte(`{"policy":[{"from": "pomerium.io","to":"%"}]}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := new(Options)

			tempFile, _ := ioutil.TempFile("", "*.json")
			defer tempFile.Close()
			defer os.Remove(tempFile.Name())
			tempFile.Write(tt.policyBytes)
			o = new(Options)
			viper.SetConfigFile(tempFile.Name())
			err := viper.ReadInConfig()
			err = o.parsePolicy()
			if (err != nil) != tt.wantErr {
				t.Errorf("parasePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(o.Policies, tt.want) {
				t.Errorf("parasePolicy() = \n%v, want \n%v", o, tt.want)
			}
		})
	}
}
