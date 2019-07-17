package config

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/viper"
)

func Test_validate(t *testing.T) {
	testOptions := func() Options {
		o := defaultOptions
		o.SharedKey = "test"
		o.Services = "all"
		return o
	}
	good := testOptions()
	badServices := testOptions()
	badServices.Services = "blue"
	badSecret := testOptions()
	badSecret.SharedKey = ""
	badSecret.Services = "authenticate"
	badSecretAllServices := testOptions()
	badSecretAllServices.SharedKey = ""

	badPolicyFile := testOptions()
	badPolicyFile.PolicyFile = "file"

	tests := []struct {
		name     string
		testOpts Options
		wantErr  bool
	}{
		{"good default with no env settings", good, false},
		{"invalid service type", badServices, true},
		{"missing shared secret", badSecret, true},
		{"missing shared secret but all service", badSecretAllServices, false},
		{"policy file specified", badPolicyFile, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testOpts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("optionsFromEnvConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_bindEnvs(t *testing.T) {
	o := &Options{}
	os.Clearenv()
	defer os.Unsetenv("POMERIUM_DEBUG")
	defer os.Unsetenv("POLICY")
	defer os.Unsetenv("HEADERS")
	os.Setenv("POMERIUM_DEBUG", "true")
	os.Setenv("POLICY", "mypolicy")
	os.Setenv("HEADERS", `{"X-Custom-1":"foo", "X-Custom-2":"bar"}`)
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
	if o.HeadersEnv != `{"X-Custom-1":"foo", "X-Custom-2":"bar"}` {
		t.Errorf("Failed to bind headers env var to HeadersEnv")
	}
}

func Test_parseHeaders(t *testing.T) {
	tests := []struct {
		name         string
		want         map[string]string
		envHeaders   string
		viperHeaders interface{}
		wantErr      bool
	}{
		{"good env", map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"}, `{"X-Custom-1":"foo", "X-Custom-2":"bar"}`, map[string]string{"X": "foo"}, false},
		{"good env not_json", map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"}, `X-Custom-1:foo,X-Custom-2:bar`, map[string]string{"X": "foo"}, false},
		{"bad env", map[string]string{}, "xyyyy", map[string]string{"X": "foo"}, true},
		{"bad env not_json", map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"}, `X-Custom-1:foo,X-Custom-2bar`, map[string]string{"X": "foo"}, true},
		{"bad viper", map[string]string{}, "", "notaheaderstruct", true},
		{"good viper", map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"}, "", map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := defaultOptions
			viper.Set("headers", tt.viperHeaders)
			viper.Set("HeadersEnv", tt.envHeaders)
			o.HeadersEnv = tt.envHeaders

			err := o.parseHeaders()

			if (err != nil) != tt.wantErr {
				t.Errorf("Error condition unexpected: err=%s", err)
			}

			if !tt.wantErr && !cmp.Equal(tt.want, o.Headers) {
				t.Errorf("Did get expected headers: %s", cmp.Diff(tt.want, o.Headers))
			}
			viper.Reset()
		})
	}

}

func Test_OptionsFromViper(t *testing.T) {
	viper.Reset()

	testPolicy := Policy{
		To:   "https://httpbin.org",
		From: "https://pomerium.io",
	}
	if err := testPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	testPolicies := []Policy{
		testPolicy,
	}

	goodConfigBytes := []byte(`{"authorize_service_url":"https://authorize.corp.example","authenticate_service_url":"https://authenticate.corp.example","shared_secret":"Setec Astronomy","service":"all","policy":[{"from":"https://pomerium.io","to":"https://httpbin.org"}]}`)
	goodOptions := defaultOptions
	goodOptions.SharedKey = "Setec Astronomy"
	goodOptions.Services = "all"
	goodOptions.Policies = testPolicies
	goodOptions.CookieName = "oatmeal"
	goodOptions.AuthorizeURLString = "https://authorize.corp.example"
	goodOptions.AuthenticateURLString = "https://authenticate.corp.example"
	authorize, err := url.Parse(goodOptions.AuthorizeURLString)
	if err != nil {
		t.Fatal(err)
	}
	authenticate, err := url.Parse(goodOptions.AuthenticateURLString)
	if err != nil {
		t.Fatal(err)
	}
	goodOptions.AuthorizeURL = authorize
	goodOptions.AuthenticateURL = authenticate
	if err := goodOptions.Validate(); err != nil {
		t.Fatal(err)
	}
	badConfigBytes := []byte("badjson!")
	badUnmarshalConfigBytes := []byte(`"debug": "blue"`)

	tests := []struct {
		name        string
		configBytes []byte
		want        *Options
		wantErr     bool
	}{
		{"good", goodConfigBytes, &goodOptions, false},
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
				t.Errorf("OptionsFromViper() error = \n%v, wantErr \n%v", err, tt.wantErr)
			}
			if tt.want != nil {
				if err := tt.want.Validate(); err != nil {
					t.Fatal(err)
				}
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("OptionsFromViper() = \n%s\n, \ngot\n%+v\n, want \n%+v", diff, got, tt.want)
			}

		})
	}

	// Test for missing config file
	_, err = OptionsFromViper("filedoesnotexist")
	if err == nil {
		t.Errorf("OptionsFromViper(): Did when loading missing file")
	}
}

func Test_parsePolicyEnv(t *testing.T) {
	t.Parallel()
	viper.Reset()

	source := "https://pomerium.io"
	sourceURL, _ := url.ParseRequestURI(source)
	dest := "https://httpbin.org"
	destURL, _ := url.ParseRequestURI(dest)

	tests := []struct {
		name        string
		policyBytes []byte
		want        []Policy
		wantErr     bool
	}{
		{"simple json", []byte(fmt.Sprintf(`[{"from": "%s","to":"%s"}]`, source, dest)), []Policy{{From: source, To: dest, Source: sourceURL, Destination: destURL}}, false},
		{"bad from", []byte(`[{"from": "%","to":"httpbin.org"}]`), []Policy{{From: "%", To: "httpbin.org"}}, true},
		{"bad to", []byte(`[{"from": "pomerium.io","to":"%"}]`), []Policy{{From: "pomerium.io", To: "%"}}, true},
		{"simple error", []byte(`{}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := new(Options)

			o.PolicyEnv = base64.StdEncoding.EncodeToString(tt.policyBytes)
			err := o.parsePolicy()
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePolicyEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(o.Policies, tt.want); diff != "" {
				t.Errorf("parsePolicyEnv() = %s", diff)
			}
		})
	}

	// Catch bad base64
	o := new(Options)
	o.PolicyEnv = "foo"
	err := o.parsePolicy()
	if err == nil {
		t.Errorf("parsePolicyEnv() did not catch bad base64 %v", o)
	}
}

func Test_parsePolicyFile(t *testing.T) {
	viper.Reset()
	source := "https://pomerium.io"
	sourceURL, _ := url.ParseRequestURI(source)
	dest := "https://httpbin.org"
	destURL, _ := url.ParseRequestURI(dest)

	tests := []struct {
		name        string
		policyBytes []byte
		want        []Policy
		wantErr     bool
	}{
		{"simple json", []byte(fmt.Sprintf(`{"policy":[{"from": "%s","to":"%s"}]}`, source, dest)), []Policy{{From: source, To: dest, Source: sourceURL, Destination: destURL}}, false},
		{"bad from", []byte(`{"policy":[{"from": "%","to":"httpbin.org"}]}`), nil, true},
		{"bad to", []byte(`{"policy":[{"from": "pomerium.io","to":"%"}]}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, _ := ioutil.TempFile("", "*.json")
			defer tempFile.Close()
			defer os.Remove(tempFile.Name())
			tempFile.Write(tt.policyBytes)
			o := new(Options)
			viper.SetConfigFile(tempFile.Name())
			if err := viper.ReadInConfig(); err != nil {
				t.Fatal(err)
			}
			err := o.parsePolicy()
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePolicyEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if diff := cmp.Diff(o.Policies, tt.want); diff != "" {
					t.Errorf("parsePolicyEnv() = diff:%s", diff)
				}
			}

		})
	}
}

func Test_Checksum(t *testing.T) {
	o := defaultOptions

	oldChecksum := o.Checksum()
	o.SharedKey = "changemeplease"
	newChecksum := o.Checksum()

	if newChecksum == oldChecksum {
		t.Errorf("Checksum() failed to update old = %s, new = %s", oldChecksum, newChecksum)
	}

	if newChecksum == "" || oldChecksum == "" {
		t.Error("Checksum() not returning data")
	}

	if o.Checksum() != newChecksum {
		t.Error("Checksum() inconsistent")
	}
}

func TestNewOptions(t *testing.T) {
	viper.Reset()
	tests := []struct {
		name            string
		authenticateURL string
		authorizeURL    string
		want            *Options
		wantErr         bool
	}{
		{"good", "https://authenticate.example", "https://authorize.example", nil, false},
		{"bad authenticate url no scheme", "authenticate.example", "https://authorize.example", nil, true},
		{"bad authenticate url no host", "https://", "https://authorize.example", nil, true},
		{"bad authorize url no scheme", "https://authenticate.example", "authorize.example", nil, true},
		{"bad authorize url no host", "https://authenticate.example", "https://", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOptions(tt.authenticateURL, tt.authorizeURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestOptionsFromViper(t *testing.T) {
	opts := []cmp.Option{
		cmpopts.IgnoreFields(Options{}, "AuthenticateInternalAddr", "DefaultUpstreamTimeout", "CookieRefresh", "CookieExpire", "Services", "Addr", "RefreshCooldown", "LogLevel", "KeyFile", "CertFile", "SharedKey", "ReadTimeout", "ReadHeaderTimeout", "IdleTimeout"),
		cmpopts.IgnoreFields(Policy{}, "Source", "Destination"),
	}

	tests := []struct {
		name        string
		configBytes []byte
		want        *Options
		wantErr     bool
	}{
		{"good",
			[]byte(`{"policy":[{"from": "https://from.example","to":"https://to.example"}]}`),
			&Options{
				Policies:       []Policy{{From: "https://from.example", To: "https://to.example"}},
				CookieName:     "_pomerium",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				Headers: map[string]string{
					"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
					"X-Content-Type-Options":    "nosniff",
					"X-Frame-Options":           "SAMEORIGIN",
					"X-XSS-Protection":          "1; mode=block",
				}},
			false},
		{"good with authenticate internal url",
			[]byte(`{"authenticate_internal_url": "https://internal.example","policy":[{"from": "https://from.example","to":"https://to.example"}]}`),
			&Options{
				AuthenticateInternalAddrString: "https://internal.example",
				Policies:                       []Policy{{From: "https://from.example", To: "https://to.example"}},
				CookieName:                     "_pomerium",
				CookieSecure:                   true,
				CookieHTTPOnly:                 true,
				Headers: map[string]string{
					"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
					"X-Content-Type-Options":    "nosniff",
					"X-Frame-Options":           "SAMEORIGIN",
					"X-XSS-Protection":          "1; mode=block",
				}},
			false},
		{"good disable header",
			[]byte(`{"headers": {"disable":"true"},"policy":[{"from": "https://from.example","to":"https://to.example"}]}`),
			&Options{
				Policies:       []Policy{{From: "https://from.example", To: "https://to.example"}},
				CookieName:     "_pomerium",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				Headers:        map[string]string{}},
			false},
		{"bad  authenticate internal url", []byte(`{"authenticate_internal_url": "internal.example","policy":[{"from": "https://from.example","to":"https://to.example"}]}`), nil, true},
		{"bad url", []byte(`{"policy":[{"from": "https://","to":"https://to.example"}]}`), nil, true},
		{"bad policy", []byte(`{"policy":[{"allow_public_unauthenticated_access": "dog","to":"https://to.example"}]}`), nil, true},

		{"bad file", []byte(`{''''}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, _ := ioutil.TempFile("", "*.json")
			defer tempFile.Close()
			defer os.Remove(tempFile.Name())
			tempFile.Write(tt.configBytes)
			got, err := OptionsFromViper(tempFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("OptionsFromViper() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, opts...); diff != "" {
				t.Errorf("NewOptions() = %s", diff)
			}
		})
	}
}

func Test_parseOptions(t *testing.T) {
	viper.Reset()

	tests := []struct {
		name             string
		envKey           string
		envValue         string
		servicesEnvKey   string
		servicesEnvValue string
		wantSharedKey    string
		wantErr          bool
	}{
		{"no shared secret", "", "", "SERVICES", "authenticate", "skip", true},
		{"no shared secret in all mode", "", "", "", "", "", false},
		{"good", "SHARED_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", "", "", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(tt.servicesEnvKey, tt.servicesEnvValue)
			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)
			defer os.Unsetenv(tt.servicesEnvKey)

			got, err := ParseOptions("")
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && got.Services != "all" && got.SharedKey != tt.wantSharedKey {
				t.Errorf("ParseOptions()\n")
				t.Errorf("got: %+v\n", got.SharedKey)
				t.Errorf("want: %+v\n", tt.wantSharedKey)

			}
		})
	}
}

type mockService struct {
	fail    bool
	Updated bool
}

func (m *mockService) UpdateOptions(o Options) error {

	m.Updated = true
	if m.fail {
		return fmt.Errorf("failed")
	}
	return nil
}

func Test_HandleConfigUpdate(t *testing.T) {
	os.Clearenv()
	os.Setenv("SHARED_SECRET", "foo")
	defer os.Unsetenv("SHARED_SECRET")

	blankOpts, err := NewOptions("https://authenticate.example", "https://authorize.example")
	if err != nil {
		t.Fatal(err)
	}

	goodOpts, err := OptionsFromViper("")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		service    *mockService
		oldOpts    Options
		wantUpdate bool
	}{
		{"good", &mockService{fail: false}, *blankOpts, true},
		{"bad", &mockService{fail: true}, *blankOpts, true},
		{"no change", &mockService{fail: false}, *goodOpts, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			HandleConfigUpdate("", &tt.oldOpts, []OptionsUpdater{tt.service})
			if tt.service.Updated != tt.wantUpdate {
				t.Errorf("Failed to update config on service")
			}
		})
	}
}
