package config

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cmpOptIgnoreUnexported = cmpopts.IgnoreUnexported(Options{})

func Test_Validate(t *testing.T) {
	t.Parallel()
	testOptions := func() *Options {
		o := NewDefaultOptions()

		o.SharedKey = "test"
		o.Services = "all"
		o.CertFile = "./testdata/example-cert.pem"
		o.KeyFile = "./testdata/example-key.pem"
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
	invalidStorageType := testOptions()
	invalidStorageType.DataBrokerStorageType = "foo"
	missingStorageDSN := testOptions()
	missingStorageDSN.DataBrokerStorageType = "redis"
	badSignoutRedirectURL := testOptions()
	badSignoutRedirectURL.SignOutRedirectURLString = "--"

	missingSharedSecretWithPersistence := testOptions()
	missingSharedSecretWithPersistence.SharedKey = ""
	missingSharedSecretWithPersistence.DataBrokerStorageType = StorageRedisName
	missingSharedSecretWithPersistence.DataBrokerStorageConnectionString = "redis://somehost:6379"

	tests := []struct {
		name     string
		testOpts *Options
		wantErr  bool
	}{
		{"good default with no env settings", good, false},
		{"invalid service type", badServices, true},
		{"missing shared secret", badSecret, true},
		{"missing shared secret but all service", badSecretAllServices, false},
		{"policy file specified", badPolicyFile, true},
		{"invalid databroker storage type", invalidStorageType, true},
		{"missing databroker storage dsn", missingStorageDSN, true},
		{"invalid signout redirect url", badSignoutRedirectURL, true},
		{"no shared key with databroker persistence", missingSharedSecretWithPersistence, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testOpts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_bindEnvs(t *testing.T) {
	o := new(Options)
	o.viper = viper.New()
	v := viper.New()
	os.Clearenv()
	defer os.Unsetenv("POMERIUM_DEBUG")
	defer os.Unsetenv("POLICY")
	defer os.Unsetenv("HEADERS")
	os.Setenv("POMERIUM_DEBUG", "true")
	os.Setenv("POLICY", "LSBmcm9tOiBodHRwczovL2h0dHBiaW4ubG9jYWxob3N0LnBvbWVyaXVtLmlvCiAgdG86IAogICAgLSBodHRwOi8vbG9jYWxob3N0OjgwODEsMQo=")
	os.Setenv("HEADERS", `{"X-Custom-1":"foo", "X-Custom-2":"bar"}`)
	err := bindEnvs(o, v)
	if err != nil {
		t.Fatalf("failed to bind options to env vars: %s", err)
	}
	err = v.Unmarshal(o, viperPolicyHooks)
	if err != nil {
		t.Errorf("Could not unmarshal %#v: %s", o, err)
	}
	o.viper = v
	if !o.Debug {
		t.Errorf("Failed to load POMERIUM_DEBUG from environment")
	}
	if len(o.Policies) != 1 {
		t.Error("failed to bind POLICY env")
	}
	if o.Services != "" {
		t.Errorf("Somehow got SERVICES from environment without configuring it")
	}
	if o.HeadersEnv != `{"X-Custom-1":"foo", "X-Custom-2":"bar"}` {
		t.Errorf("Failed to bind headers env var to HeadersEnv")
	}
}

func Test_parseHeaders(t *testing.T) {
	// t.Parallel()
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
			var (
				o  *Options
				mu sync.Mutex
			)
			mu.Lock()
			defer mu.Unlock()
			o = NewDefaultOptions()
			o.viperSet("headers", tt.viperHeaders)
			o.viperSet("HeadersEnv", tt.envHeaders)
			o.HeadersEnv = tt.envHeaders
			err := o.parseHeaders()

			if (err != nil) != tt.wantErr {
				t.Errorf("Error condition unexpected: err=%s", err)
			}

			if !tt.wantErr && !cmp.Equal(tt.want, o.Headers) {
				t.Errorf("Did get expected headers: %s", cmp.Diff(tt.want, o.Headers))
			}
		})
	}
}

func Test_parsePolicyFile(t *testing.T) {
	t.Parallel()

	opts := []cmp.Option{
		cmpopts.IgnoreFields(Policy{}, "EnvoyOpts"),
		cmpOptIgnoreUnexported,
	}

	source := "https://pomerium.io"
	sourceURL, _ := url.ParseRequestURI(source)

	to, err := ParseWeightedURL("https://httpbin.org")
	require.NoError(t, err)

	tests := []struct {
		name        string
		policyBytes []byte
		want        []Policy
		wantErr     bool
	}{
		{
			"simple json",
			[]byte(fmt.Sprintf(`{"policy":[{"from": "%s","to":"%s"}]}`, source, to.URL.String())),
			[]Policy{{
				From:   source,
				To:     []WeightedURL{*to},
				Source: &StringURL{sourceURL},
			}},
			false,
		},
		{"bad from", []byte(`{"policy":[{"from": "%","to":"httpbin.org"}]}`), nil, true},
		{"bad to", []byte(`{"policy":[{"from": "pomerium.io","to":"%"}]}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, _ := ioutil.TempFile("", "*.json")
			defer tempFile.Close()
			defer os.Remove(tempFile.Name())
			tempFile.Write(tt.policyBytes)
			var o Options
			o.viper = viper.New()
			o.viper.SetConfigFile(tempFile.Name())
			if err := o.viper.ReadInConfig(); err != nil {
				t.Fatal(err)
			}
			err := o.parsePolicy()
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePolicyEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if diff := cmp.Diff(o.Policies, tt.want, opts...); diff != "" {
					t.Errorf("parsePolicyEnv() = diff:%s", diff)
				}
			}
		})
	}
}

func Test_Checksum(t *testing.T) {
	o := NewDefaultOptions()

	oldChecksum := o.Checksum()
	o.SharedKey = "changemeplease"
	newChecksum := o.Checksum()

	if newChecksum == oldChecksum {
		t.Errorf("Checksum() failed to update old = %d, new = %d", oldChecksum, newChecksum)
	}

	if newChecksum == 0 || oldChecksum == 0 {
		t.Error("Checksum() not returning data")
	}

	if o.Checksum() != newChecksum {
		t.Error("Checksum() inconsistent")
	}
}

func TestOptionsFromViper(t *testing.T) {
	opts := []cmp.Option{
		cmpopts.IgnoreFields(Options{}, "CookieSecret", "GRPCInsecure", "GRPCAddr", "DataBrokerURLString", "DataBrokerURL", "AuthorizeURL", "AuthorizeURLString", "DefaultUpstreamTimeout", "CookieExpire", "Services", "Addr", "RefreshCooldown", "LogLevel", "KeyFile", "CertFile", "SharedKey", "ReadTimeout", "IdleTimeout", "GRPCClientTimeout", "GRPCClientDNSRoundRobin", "TracingSampleRate"),
		cmpopts.IgnoreFields(Policy{}, "Source", "EnvoyOpts"),
		cmpOptIgnoreUnexported,
	}

	tests := []struct {
		name        string
		configBytes []byte
		want        *Options
		wantErr     bool
	}{
		{
			"good",
			[]byte(`{"autocert_dir":"","insecure_server":true,"policy":[{"from": "https://from.example","to":"https://to.example"}]}`),
			&Options{
				Policies:                        []Policy{{From: "https://from.example", To: mustParseWeightedURLs(t, "https://to.example")}},
				CookieName:                      "_pomerium",
				CookieSecure:                    true,
				InsecureServer:                  true,
				CookieHTTPOnly:                  true,
				GRPCServerMaxConnectionAge:      5 * time.Minute,
				GRPCServerMaxConnectionAgeGrace: 5 * time.Minute,
				AuthenticateCallbackPath:        "/oauth2/callback",
				Headers: map[string]string{
					"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
					"X-Frame-Options":           "SAMEORIGIN",
					"X-XSS-Protection":          "1; mode=block",
				},
				RefreshDirectoryTimeout:  1 * time.Minute,
				RefreshDirectoryInterval: 10 * time.Minute,
				QPS:                      1.0,
				DataBrokerStorageType:    "memory",
				EnvoyAdminAccessLogPath:  os.DevNull,
				EnvoyAdminProfilePath:    os.DevNull,
				EnvoyAdminAddress:        "127.0.0.1:9901",
			},
			false,
		},
		{
			"good disable header",
			[]byte(`{"autocert_dir":"","insecure_server":true,"headers": {"disable":"true"},"policy":[{"from": "https://from.example","to":"https://to.example"}]}`),
			&Options{
				Policies:                        []Policy{{From: "https://from.example", To: mustParseWeightedURLs(t, "https://to.example")}},
				CookieName:                      "_pomerium",
				AuthenticateCallbackPath:        "/oauth2/callback",
				CookieSecure:                    true,
				CookieHTTPOnly:                  true,
				InsecureServer:                  true,
				GRPCServerMaxConnectionAge:      5 * time.Minute,
				GRPCServerMaxConnectionAgeGrace: 5 * time.Minute,
				Headers:                         map[string]string{},
				RefreshDirectoryTimeout:         1 * time.Minute,
				RefreshDirectoryInterval:        10 * time.Minute,
				QPS:                             1.0,
				DataBrokerStorageType:           "memory",
				EnvoyAdminAccessLogPath:         os.DevNull,
				EnvoyAdminProfilePath:           os.DevNull,
				EnvoyAdminAddress:               "127.0.0.1:9901",
			},
			false,
		},
		{"bad url", []byte(`{"policy":[{"from": "https://","to":"https://to.example"}]}`), nil, true},
		{"bad policy", []byte(`{"policy":[{"allow_public_unauthenticated_access": "dog","to":"https://to.example"}]}`), nil, true},
		{"bad file", []byte(`{''''}`), nil, true},
		{"allowed_groups without idp_service_account should fail", []byte(`{"autocert_dir":"","insecure_server":true,"policy":[{"from": "https://from.example","to":"https://to.example","allowed_groups": "['group1']"}]}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, _ := ioutil.TempFile("", "*.json")
			defer tempFile.Close()
			defer os.Remove(tempFile.Name())
			tempFile.Write(tt.configBytes)
			got, err := optionsFromViper(tempFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("optionsFromViper() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, opts...); diff != "" {
				t.Errorf("newOptionsFromConfig() = %s", diff)
			}
		})
	}
}

func Test_NewOptionsFromConfigEnvVar(t *testing.T) {
	tests := []struct {
		name        string
		envKeyPairs map[string]string
		wantErr     bool
	}{
		{"good", map[string]string{"INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad no shared secret", map[string]string{"INSECURE_SERVER": "true", "SERVICES": "authenticate"}, true},
		{"good no shared secret in all mode", map[string]string{"INSECURE_SERVER": "true"}, false},
		{"bad header", map[string]string{"HEADERS": "x;y;z", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad authenticate url", map[string]string{"AUTHENTICATE_SERVICE_URL": "authenticate.example", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad authorize url", map[string]string{"AUTHORIZE_SERVICE_URL": "authorize.example", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad cert base64", map[string]string{"CERTIFICATE": "bad cert", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad cert key base64", map[string]string{"CERTIFICATE_KEY": "bad cert", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad no certs no insecure mode set", map[string]string{"SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"good disable headers ", map[string]string{"HEADERS": "disable:true", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad whitespace in secret", map[string]string{"INSECURE_SERVER": "true", "SERVICES": "authenticate", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=\n"}, true},
		{"good forward auth url", map[string]string{"FORWARD_AUTH_URL": "https://databroker.example", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad forward auth url", map[string]string{"FORWARD_AUTH_URL": "databroker.example", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"same addr and grpc addr", map[string]string{"SERVICES": "databroker", "ADDRESS": "0", "GRPC_ADDRESS": "0", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad cert files", map[string]string{"INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", "CERTIFICATES": "./test-data/example-cert.pem"}, true},
		{"good cert file", map[string]string{"CERTIFICATE_FILE": "./testdata/example-cert.pem", "CERTIFICATE_KEY_FILE": "./testdata/example-key.pem", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad cert file", map[string]string{"CERTIFICATE_FILE": "./testdata/example-cert-bad.pem", "CERTIFICATE_KEY_FILE": "./testdata/example-key-bad.pem", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"good client ca file", map[string]string{"CLIENT_CA_FILE": "./testdata/ca.pem", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad client ca file", map[string]string{"CLIENT_CA_FILE": "./testdata/bad-ca.pem", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad client ca b64", map[string]string{"CLIENT_CA": "bad cert", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envKeyPairs {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			_, err := newOptionsFromConfig("")
			if (err != nil) != tt.wantErr {
				t.Errorf("newOptionsFromConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_AutoCertOptionsFromEnvVar(t *testing.T) {
	envs := map[string]string{
		"AUTOCERT":             "true",
		"AUTOCERT_DIR":         "/test",
		"AUTOCERT_MUST_STAPLE": "true",

		"INSECURE_SERVER": "true",
	}
	for k, v := range envs {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	o, err := newOptionsFromConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if !o.AutocertOptions.Enable {
		t.Error("o.AutocertOptions.Enable: want true, got false")
	}
	if !o.AutocertOptions.MustStaple {
		t.Error("o.AutocertOptions.MustStaple: want true, got false")
	}
	if o.AutocertOptions.Folder != "/test" {
		t.Errorf("o.AutocertOptions.Folder: want /test, got %s", o.AutocertOptions.Folder)
	}
}

func TestHTTPRedirectAddressStripQuotes(t *testing.T) {
	o := NewDefaultOptions()
	o.InsecureServer = true
	o.HTTPRedirectAddr = `":80"`
	assert.NoError(t, o.Validate())
	assert.Equal(t, ":80", o.HTTPRedirectAddr)
}

func TestCertificatesArrayParsing(t *testing.T) {
	t.Parallel()

	testCertFileRef := "./testdata/example-cert.pem"
	testKeyFileRef := "./testdata/example-key.pem"
	testCertFile, _ := ioutil.ReadFile(testCertFileRef)
	testKeyFile, _ := ioutil.ReadFile(testKeyFileRef)
	testCertAsBase64 := base64.StdEncoding.EncodeToString(testCertFile)
	testKeyAsBase64 := base64.StdEncoding.EncodeToString(testKeyFile)

	tests := []struct {
		name             string
		certificateFiles []certificateFilePair
		wantErr          bool
	}{
		{"Handles base64 string as params", []certificateFilePair{{KeyFile: testKeyAsBase64, CertFile: testCertAsBase64}}, false},
		{"Handles file reference as params", []certificateFilePair{{KeyFile: testKeyFileRef, CertFile: testCertFileRef}}, false},
		{"Returns an error otherwise", []certificateFilePair{{KeyFile: "abc", CertFile: "abc"}}, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			o := NewDefaultOptions()
			o.CertificateFiles = tt.certificateFiles
			err := o.Validate()

			if err != nil && tt.wantErr == false {
				t.Fatal(err)
			}
		})
	}
}

func TestCompareByteSliceSlice(t *testing.T) {
	type Bytes = [][]byte

	tests := []struct {
		expect int
		a      Bytes
		b      Bytes
	}{
		{
			0,
			Bytes{
				{0, 1, 2, 3},
			},
			Bytes{
				{0, 1, 2, 3},
			},
		},
		{
			-1,
			Bytes{
				{0, 1, 2, 3},
			},
			Bytes{
				{0, 1, 2, 4},
			},
		},
		{
			1,
			Bytes{
				{0, 1, 2, 4},
			},
			Bytes{
				{0, 1, 2, 3},
			},
		},
		{
			-1,
			Bytes{
				{0, 1, 2, 3},
			},
			Bytes{
				{0, 1, 2, 3},
				{4, 5, 6, 7},
			},
		},
		{
			1,
			Bytes{
				{0, 1, 2, 3},
				{4, 5, 6, 7},
			},
			Bytes{
				{0, 1, 2, 3},
			},
		},
	}
	for _, tt := range tests {
		actual := compareByteSliceSlice(tt.a, tt.b)
		if tt.expect != actual {
			t.Errorf("expected compare(%v, %v) to be %v but got %v",
				tt.a, tt.b, tt.expect, actual)
		}
	}
}

func TestOptions_DefaultURL(t *testing.T) {
	t.Parallel()

	defaultOptions := &Options{}
	opts := &Options{
		AuthenticateURL: mustParseURL("https://authenticate.example.com"),
		AuthorizeURL:    mustParseURL("https://authorize.example.com"),
		DataBrokerURL:   mustParseURL("https://databroker.example.com"),
		ForwardAuthURL:  mustParseURL("https://forwardauth.example.com"),
	}
	tests := []struct {
		name           string
		f              func() (*url.URL, error)
		expectedURLStr string
	}{
		{"default authenticate url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"default authorize url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"default databroker url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"default forward auth url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"good authenticate url", opts.GetAuthenticateURL, "https://authenticate.example.com"},
		{"good authorize url", opts.GetAuthorizeURL, "https://authorize.example.com"},
		{"good databroker url", opts.GetDataBrokerURL, "https://databroker.example.com"},
		{"good forward auth url", opts.GetForwardAuthURL, "https://forwardauth.example.com"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := tc.f()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedURLStr, u.String())
		})
	}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func TestOptions_GetOauthOptions(t *testing.T) {
	opts := &Options{AuthenticateURL: mustParseURL("https://authenticate.example.com")}
	oauthOptions, err := opts.GetOauthOptions()
	require.NoError(t, err)

	// Test that oauth redirect url hostname must point to authenticate url hostname.
	assert.Equal(t, opts.AuthenticateURL.Hostname(), oauthOptions.RedirectURL.Hostname())
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []WeightedURL {
	wu, err := ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
