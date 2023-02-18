package config

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
)

var cmpOptIgnoreUnexported = cmpopts.IgnoreUnexported(Options{}, Policy{})

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
	err = v.Unmarshal(o, ViperPolicyHooks)
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
		{
			"good env",
			map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"},
			`{"X-Custom-1":"foo", "X-Custom-2":"bar"}`,
			map[string]string{"X": "foo"},
			false,
		},
		{
			"good env not_json",
			map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"},
			`X-Custom-1:foo,X-Custom-2:bar`,
			map[string]string{"X": "foo"},
			false,
		},
		{
			"bad env",
			map[string]string{},
			"xyyyy",
			map[string]string{"X": "foo"},
			true,
		},
		{
			"bad env not_json",
			map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"},
			`X-Custom-1:foo,X-Custom-2bar`,
			map[string]string{"X": "foo"},
			true,
		},
		{
			"bad viper",
			map[string]string{},
			"",
			"notaheaderstruct",
			true,
		},
		{
			"good viper",
			map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"},
			"",
			map[string]string{"X-Custom-1": "foo", "X-Custom-2": "bar"},
			false,
		},
		{
			"new field name",
			map[string]string{"X-Custom-1": "foo"},
			"",
			map[string]string{"X-Custom-1": "foo"},
			false,
		},
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
			o.viperSet("set_response_headers", tt.viperHeaders)
			o.viperSet("HeadersEnv", tt.envHeaders)
			o.HeadersEnv = tt.envHeaders
			err := o.parseHeaders(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("Error condition unexpected: err=%s", err)
			}

			if !tt.wantErr && !cmp.Equal(tt.want, o.SetResponseHeaders) {
				t.Errorf("Did get expected headers: %s", cmp.Diff(tt.want, o.SetResponseHeaders))
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
			tempFile, _ := os.CreateTemp("", "*.json")
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
		cmpopts.IgnoreFields(Options{}, "CookieSecret", "GRPCInsecure", "GRPCAddr", "DataBrokerURLString", "DataBrokerURLStrings", "AuthorizeURLString", "AuthorizeURLStrings", "DefaultUpstreamTimeout", "CookieExpire", "Services", "Addr", "LogLevel", "KeyFile", "CertFile", "SharedKey", "ReadTimeout", "IdleTimeout", "GRPCClientTimeout", "GRPCClientDNSRoundRobin", "TracingSampleRate", "ProgrammaticRedirectDomainWhitelist"),
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
				Policies:                 []Policy{{From: "https://from.example", To: mustParseWeightedURLs(t, "https://to.example")}},
				CookieName:               "_pomerium",
				CookieSecure:             true,
				InsecureServer:           true,
				CookieHTTPOnly:           true,
				AuthenticateCallbackPath: "/oauth2/callback",
				DataBrokerStorageType:    "memory",
				EnvoyAdminAccessLogPath:  os.DevNull,
				EnvoyAdminProfilePath:    os.DevNull,
			},
			false,
		},
		{
			"good disable header",
			[]byte(`{"autocert_dir":"","insecure_server":true,"set_response_headers": {"disable":"true"},"policy":[{"from": "https://from.example","to":"https://to.example"}]}`),
			&Options{
				Policies:                 []Policy{{From: "https://from.example", To: mustParseWeightedURLs(t, "https://to.example")}},
				CookieName:               "_pomerium",
				AuthenticateCallbackPath: "/oauth2/callback",
				CookieSecure:             true,
				CookieHTTPOnly:           true,
				InsecureServer:           true,
				SetResponseHeaders:       map[string]string{"disable": "true"},
				DataBrokerStorageType:    "memory",
				EnvoyAdminAccessLogPath:  os.DevNull,
				EnvoyAdminProfilePath:    os.DevNull,
			},
			false,
		},
		{"bad url", []byte(`{"policy":[{"from": "https://","to":"https://to.example"}]}`), nil, true},
		{"bad policy", []byte(`{"policy":[{"allow_public_unauthenticated_access": "dog","to":"https://to.example"}]}`), nil, true},
		{"bad file", []byte(`{''''}`), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, _ := os.CreateTemp("", "*.json")
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
		{"no certs no insecure mode set", map[string]string{"SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"good disable headers ", map[string]string{"HEADERS": "disable:true", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad whitespace in secret", map[string]string{"INSECURE_SERVER": "true", "SERVICES": "authenticate", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=\n"}, true},
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
	type test struct {
		envs     map[string]string
		expected AutocertOptions
		wantErr  bool
		cleanup  func()
	}

	tests := map[string]func(t *testing.T) test{
		"ok/simple": func(t *testing.T) test {
			envs := map[string]string{
				"AUTOCERT":             "true",
				"AUTOCERT_DIR":         "/test",
				"AUTOCERT_MUST_STAPLE": "true",

				"INSECURE_SERVER": "true",
			}
			return test{
				envs: envs,
				expected: AutocertOptions{
					Enable:     true,
					Folder:     "/test",
					MustStaple: true,
				},
				wantErr: false,
			}
		},
		"ok/custom-ca": func(t *testing.T) test {
			certPEM, err := newCACertPEM()
			require.NoError(t, err)
			envs := map[string]string{
				"AUTOCERT":             "true",
				"AUTOCERT_CA":          "test-ca.example.com/directory",
				"AUTOCERT_EMAIL":       "test@example.com",
				"AUTOCERT_EAB_KEY_ID":  "keyID",
				"AUTOCERT_EAB_MAC_KEY": "fake-key",
				"AUTOCERT_TRUSTED_CA":  base64.StdEncoding.EncodeToString(certPEM),
				"AUTOCERT_DIR":         "/test",
				"AUTOCERT_MUST_STAPLE": "true",

				"INSECURE_SERVER": "true",
			}
			return test{
				envs:    envs,
				wantErr: false,
				expected: AutocertOptions{
					Enable:     true,
					CA:         "test-ca.example.com/directory",
					Email:      "test@example.com",
					EABKeyID:   "keyID",
					EABMACKey:  "fake-key",
					TrustedCA:  base64.StdEncoding.EncodeToString(certPEM),
					Folder:     "/test",
					MustStaple: true,
				},
			}
		},
		"ok/custom-ca-file": func(t *testing.T) test {
			certPEM, err := newCACertPEM()
			require.NoError(t, err)
			f, err := os.CreateTemp("", "pomerium-test-ca")
			require.NoError(t, err)
			n, err := f.Write(certPEM)
			require.NoError(t, err)
			require.Equal(t, len(certPEM), n)
			envs := map[string]string{
				"AUTOCERT":                 "true",
				"AUTOCERT_CA":              "test-ca.example.com/directory",
				"AUTOCERT_EMAIL":           "test@example.com",
				"AUTOCERT_EAB_KEY_ID":      "keyID",
				"AUTOCERT_EAB_MAC_KEY":     "fake-key",
				"AUTOCERT_TRUSTED_CA_FILE": f.Name(),
				"AUTOCERT_DIR":             "/test",
				"AUTOCERT_MUST_STAPLE":     "true",

				"INSECURE_SERVER": "true",
			}
			return test{
				envs:    envs,
				wantErr: false,
				expected: AutocertOptions{
					Enable:        true,
					CA:            "test-ca.example.com/directory",
					Email:         "test@example.com",
					EABKeyID:      "keyID",
					EABMACKey:     "fake-key",
					TrustedCAFile: f.Name(),
					Folder:        "/test",
					MustStaple:    true,
				},
				cleanup: func() { os.Remove(f.Name()) },
			}
		},
	}

	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.envs {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			o, err := newOptionsFromConfig("")
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(tc.expected, o.AutocertOptions) {
				t.Errorf("AutoCertOptionsFromEnvVar() diff = %s", cmp.Diff(tc.expected, o.AutocertOptions))
			}
			if tc.cleanup != nil {
				tc.cleanup()
			}
		})
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
	testCertFile, _ := os.ReadFile(testCertFileRef)
	testKeyFile, _ := os.ReadFile(testKeyFileRef)
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

	firstURL := func(f func() ([]*url.URL, error)) func() (*url.URL, error) {
		return func() (*url.URL, error) {
			urls, err := f()
			if err != nil {
				return nil, err
			} else if len(urls) == 0 {
				return nil, fmt.Errorf("no url defined")
			}
			return urls[0], nil
		}
	}

	defaultOptions := &Options{}
	opts := &Options{
		AuthenticateURLString: "https://authenticate.example.com",
		AuthorizeURLString:    "https://authorize.example.com",
		DataBrokerURLString:   "https://databroker.example.com",
	}
	tests := []struct {
		name           string
		f              func() (*url.URL, error)
		expectedURLStr string
	}{
		{"default authenticate url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"default authorize url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"default databroker url", defaultOptions.GetAuthenticateURL, "https://127.0.0.1"},
		{"good authenticate url", opts.GetAuthenticateURL, "https://authenticate.example.com"},
		{"good authorize url", firstURL(opts.GetAuthorizeURLs), "https://authorize.example.com"},
		{"good databroker url", firstURL(opts.GetDataBrokerURLs), "https://databroker.example.com"},
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

func TestOptions_GetOauthOptions(t *testing.T) {
	opts := &Options{AuthenticateURLString: "https://authenticate.example.com"}
	oauthOptions, err := opts.GetOauthOptions()
	require.NoError(t, err)

	// Test that oauth redirect url hostname must point to authenticate url hostname.
	u, err := opts.GetAuthenticateURL()
	require.NoError(t, err)
	assert.Equal(t, u.Hostname(), oauthOptions.RedirectURL.Hostname())
}

func TestOptions_GetAllRouteableGRPCHosts(t *testing.T) {
	opts := &Options{
		AuthenticateURLString: "https://authenticate.example.com",
		AuthorizeURLString:    "https://authorize.example.com",
		DataBrokerURLString:   "https://databroker.example.com",
		Services:              "all",
	}
	hosts, err := opts.GetAllRouteableGRPCHosts()
	assert.NoError(t, err)

	assert.Equal(t, []string{
		"authorize.example.com",
		"authorize.example.com:443",
		"databroker.example.com",
		"databroker.example.com:443",
	}, hosts)
}

func TestOptions_GetAllRouteableHTTPHosts(t *testing.T) {
	p1 := Policy{From: "https://from1.example.com"}
	p1.Validate()
	p2 := Policy{From: "https://from2.example.com"}
	p2.Validate()
	p3 := Policy{From: "https://from3.example.com", TLSDownstreamServerName: "from.example.com"}
	p3.Validate()

	opts := &Options{
		AuthenticateURLString: "https://authenticate.example.com",
		AuthorizeURLString:    "https://authorize.example.com",
		DataBrokerURLString:   "https://databroker.example.com",
		Policies:              []Policy{p1, p2, p3},
		Services:              "all",
	}
	hosts, err := opts.GetAllRouteableHTTPHosts()
	assert.NoError(t, err)

	assert.Equal(t, []string{
		"authenticate.example.com",
		"authenticate.example.com:443",
		"from.example.com",
		"from.example.com:443",
		"from1.example.com",
		"from1.example.com:443",
		"from2.example.com",
		"from2.example.com:443",
		"from3.example.com",
		"from3.example.com:443",
	}, hosts)
}

func TestOptions_ApplySettings(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second)
	defer clearTimeout()

	t.Run("certificates", func(t *testing.T) {
		options := NewDefaultOptions()
		cert1, err := cryptutil.GenerateCertificate(nil, "example.com")
		require.NoError(t, err)
		options.CertificateFiles = append(options.CertificateFiles, certificateFilePair{
			CertFile: base64.StdEncoding.EncodeToString(encodeCert(cert1)),
		})
		cert2, err := cryptutil.GenerateCertificate(nil, "example.com")
		require.NoError(t, err)
		cert3, err := cryptutil.GenerateCertificate(nil, "not.example.com")
		require.NoError(t, err)

		settings := &config.Settings{
			Certificates: []*config.Settings_Certificate{
				{CertBytes: encodeCert(cert2)},
				{CertBytes: encodeCert(cert3)},
			},
		}
		options.ApplySettings(ctx, settings)
		assert.Len(t, options.CertificateFiles, 2, "should prevent adding duplicate certificates")
	})
}

func TestOptions_GetSetResponseHeaders(t *testing.T) {
	t.Run("lax", func(t *testing.T) {
		options := NewDefaultOptions()
		assert.Equal(t, map[string]string{
			"X-Frame-Options":  "SAMEORIGIN",
			"X-XSS-Protection": "1; mode=block",
		}, options.GetSetResponseHeaders(false))
	})
	t.Run("strict", func(t *testing.T) {
		options := NewDefaultOptions()
		assert.Equal(t, map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			"X-Frame-Options":           "SAMEORIGIN",
			"X-XSS-Protection":          "1; mode=block",
		}, options.GetSetResponseHeaders(true))
	})
	t.Run("disable", func(t *testing.T) {
		options := NewDefaultOptions()
		options.SetResponseHeaders = map[string]string{DisableHeaderKey: "1", "x-other": "xyz"}
		assert.Equal(t, map[string]string{}, options.GetSetResponseHeaders(true))
	})
}

func TestOptions_GetSharedKey(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		o := NewDefaultOptions()
		bs, err := o.GetSharedKey()
		assert.NoError(t, err)
		assert.Equal(t, randomSharedKey, base64.StdEncoding.EncodeToString(bs))
	})
	t.Run("missing", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Services = ServiceProxy
		_, err := o.GetSharedKey()
		assert.Error(t, err)
	})
}

func TestOptions_GetSigningKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		input  string
		output []byte
		err    error
	}{
		{"missing", "", []byte{}, nil},
		{"pem", `
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIGGh6FlBe8yy9dRJgm+35lj3naGFtDODOf6leCW1bRGwoAcGBSuBBAAK
oUQDQgAE7UlKcFatc9m3GinCrhhT2oRQZ/bEwS98iEUXr0DR8GdxH3e4fhnicsNB
jHOCur7NYTgf5VaPJwIqLGBmTwM0ew==
-----END EC PRIVATE KEY-----

-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBo4wSjkFqQrzf2APNnPol8EDZzkhpcMSaEWXg8iOkbOoAcGBSuBBAAK
oUQDQgAEr+bGqssRv8RxPV2jJbDpMw81AVXr5+Q2pIF4u6xD9r56lst8uHYThPsw
ypaqswFIkSzQSW8awdWJ5d+1DEJRUQ==
-----END EC PRIVATE KEY-----
		`, []byte{
			0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d,
			0x48, 0x51, 0x43, 0x41, 0x51, 0x45, 0x45, 0x49, 0x47, 0x47, 0x68, 0x36, 0x46, 0x6c, 0x42, 0x65,
			0x38, 0x79, 0x79, 0x39, 0x64, 0x52, 0x4a, 0x67, 0x6d, 0x2b, 0x33, 0x35, 0x6c, 0x6a, 0x33, 0x6e,
			0x61, 0x47, 0x46, 0x74, 0x44, 0x4f, 0x44, 0x4f, 0x66, 0x36, 0x6c, 0x65, 0x43, 0x57, 0x31, 0x62,
			0x52, 0x47, 0x77, 0x6f, 0x41, 0x63, 0x47, 0x42, 0x53, 0x75, 0x42, 0x42, 0x41, 0x41, 0x4b, 0x0a,
			0x6f, 0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45, 0x37, 0x55, 0x6c, 0x4b, 0x63, 0x46, 0x61, 0x74,
			0x63, 0x39, 0x6d, 0x33, 0x47, 0x69, 0x6e, 0x43, 0x72, 0x68, 0x68, 0x54, 0x32, 0x6f, 0x52, 0x51,
			0x5a, 0x2f, 0x62, 0x45, 0x77, 0x53, 0x39, 0x38, 0x69, 0x45, 0x55, 0x58, 0x72, 0x30, 0x44, 0x52,
			0x38, 0x47, 0x64, 0x78, 0x48, 0x33, 0x65, 0x34, 0x66, 0x68, 0x6e, 0x69, 0x63, 0x73, 0x4e, 0x42,
			0x0a, 0x6a, 0x48, 0x4f, 0x43, 0x75, 0x72, 0x37, 0x4e, 0x59, 0x54, 0x67, 0x66, 0x35, 0x56, 0x61,
			0x50, 0x4a, 0x77, 0x49, 0x71, 0x4c, 0x47, 0x42, 0x6d, 0x54, 0x77, 0x4d, 0x30, 0x65, 0x77, 0x3d,
			0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x0a,
			0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d,
			0x48, 0x51, 0x43, 0x41, 0x51, 0x45, 0x45, 0x49, 0x42, 0x6f, 0x34, 0x77, 0x53, 0x6a, 0x6b, 0x46,
			0x71, 0x51, 0x72, 0x7a, 0x66, 0x32, 0x41, 0x50, 0x4e, 0x6e, 0x50, 0x6f, 0x6c, 0x38, 0x45, 0x44,
			0x5a, 0x7a, 0x6b, 0x68, 0x70, 0x63, 0x4d, 0x53, 0x61, 0x45, 0x57, 0x58, 0x67, 0x38, 0x69, 0x4f,
			0x6b, 0x62, 0x4f, 0x6f, 0x41, 0x63, 0x47, 0x42, 0x53, 0x75, 0x42, 0x42, 0x41, 0x41, 0x4b, 0x0a,
			0x6f, 0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45, 0x72, 0x2b, 0x62, 0x47, 0x71, 0x73, 0x73, 0x52,
			0x76, 0x38, 0x52, 0x78, 0x50, 0x56, 0x32, 0x6a, 0x4a, 0x62, 0x44, 0x70, 0x4d, 0x77, 0x38, 0x31,
			0x41, 0x56, 0x58, 0x72, 0x35, 0x2b, 0x51, 0x32, 0x70, 0x49, 0x46, 0x34, 0x75, 0x36, 0x78, 0x44,
			0x39, 0x72, 0x35, 0x36, 0x6c, 0x73, 0x74, 0x38, 0x75, 0x48, 0x59, 0x54, 0x68, 0x50, 0x73, 0x77,
			0x0a, 0x79, 0x70, 0x61, 0x71, 0x73, 0x77, 0x46, 0x49, 0x6b, 0x53, 0x7a, 0x51, 0x53, 0x57, 0x38,
			0x61, 0x77, 0x64, 0x57, 0x4a, 0x35, 0x64, 0x2b, 0x31, 0x44, 0x45, 0x4a, 0x52, 0x55, 0x51, 0x3d,
			0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
		}, nil},
		{"base64", `
LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUdHaDZGbEJlOHl5OWRSSmdtKzM1bGozbmFHRnRET0RPZjZsZUNXMWJSR3dvQWNHQlN1QkJBQUsKb1VRRFFnQUU3VWxLY0ZhdGM5bTNHaW5DcmhoVDJvUlFaL2JFd1M5OGlFVVhyMERSOEdkeEgzZTRmaG5pY3NOQgpqSE9DdXI3TllUZ2Y1VmFQSndJcUxHQm1Ud00wZXc9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCgotLS0tLUJFR0lOIEVDIFBSSVZBVEUgS0VZLS0tLS0KTUhRQ0FRRUVJQm80d1Nqa0ZxUXJ6ZjJBUE5uUG9sOEVEWnpraHBjTVNhRVdYZzhpT2tiT29BY0dCU3VCQkFBSwpvVVFEUWdBRXIrYkdxc3NSdjhSeFBWMmpKYkRwTXc4MUFWWHI1K1EycElGNHU2eEQ5cjU2bHN0OHVIWVRoUHN3CnlwYXFzd0ZJa1N6UVNXOGF3ZFdKNWQrMURFSlJVUT09Ci0tLS0tRU5EIEVDIFBSSVZBVEUgS0VZLS0tLS0=
		`, []byte{
			0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d,
			0x48, 0x51, 0x43, 0x41, 0x51, 0x45, 0x45, 0x49, 0x47, 0x47, 0x68, 0x36, 0x46, 0x6c, 0x42, 0x65,
			0x38, 0x79, 0x79, 0x39, 0x64, 0x52, 0x4a, 0x67, 0x6d, 0x2b, 0x33, 0x35, 0x6c, 0x6a, 0x33, 0x6e,
			0x61, 0x47, 0x46, 0x74, 0x44, 0x4f, 0x44, 0x4f, 0x66, 0x36, 0x6c, 0x65, 0x43, 0x57, 0x31, 0x62,
			0x52, 0x47, 0x77, 0x6f, 0x41, 0x63, 0x47, 0x42, 0x53, 0x75, 0x42, 0x42, 0x41, 0x41, 0x4b, 0x0a,
			0x6f, 0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45, 0x37, 0x55, 0x6c, 0x4b, 0x63, 0x46, 0x61, 0x74,
			0x63, 0x39, 0x6d, 0x33, 0x47, 0x69, 0x6e, 0x43, 0x72, 0x68, 0x68, 0x54, 0x32, 0x6f, 0x52, 0x51,
			0x5a, 0x2f, 0x62, 0x45, 0x77, 0x53, 0x39, 0x38, 0x69, 0x45, 0x55, 0x58, 0x72, 0x30, 0x44, 0x52,
			0x38, 0x47, 0x64, 0x78, 0x48, 0x33, 0x65, 0x34, 0x66, 0x68, 0x6e, 0x69, 0x63, 0x73, 0x4e, 0x42,
			0x0a, 0x6a, 0x48, 0x4f, 0x43, 0x75, 0x72, 0x37, 0x4e, 0x59, 0x54, 0x67, 0x66, 0x35, 0x56, 0x61,
			0x50, 0x4a, 0x77, 0x49, 0x71, 0x4c, 0x47, 0x42, 0x6d, 0x54, 0x77, 0x4d, 0x30, 0x65, 0x77, 0x3d,
			0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x0a,
			0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d,
			0x48, 0x51, 0x43, 0x41, 0x51, 0x45, 0x45, 0x49, 0x42, 0x6f, 0x34, 0x77, 0x53, 0x6a, 0x6b, 0x46,
			0x71, 0x51, 0x72, 0x7a, 0x66, 0x32, 0x41, 0x50, 0x4e, 0x6e, 0x50, 0x6f, 0x6c, 0x38, 0x45, 0x44,
			0x5a, 0x7a, 0x6b, 0x68, 0x70, 0x63, 0x4d, 0x53, 0x61, 0x45, 0x57, 0x58, 0x67, 0x38, 0x69, 0x4f,
			0x6b, 0x62, 0x4f, 0x6f, 0x41, 0x63, 0x47, 0x42, 0x53, 0x75, 0x42, 0x42, 0x41, 0x41, 0x4b, 0x0a,
			0x6f, 0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45, 0x72, 0x2b, 0x62, 0x47, 0x71, 0x73, 0x73, 0x52,
			0x76, 0x38, 0x52, 0x78, 0x50, 0x56, 0x32, 0x6a, 0x4a, 0x62, 0x44, 0x70, 0x4d, 0x77, 0x38, 0x31,
			0x41, 0x56, 0x58, 0x72, 0x35, 0x2b, 0x51, 0x32, 0x70, 0x49, 0x46, 0x34, 0x75, 0x36, 0x78, 0x44,
			0x39, 0x72, 0x35, 0x36, 0x6c, 0x73, 0x74, 0x38, 0x75, 0x48, 0x59, 0x54, 0x68, 0x50, 0x73, 0x77,
			0x0a, 0x79, 0x70, 0x61, 0x71, 0x73, 0x77, 0x46, 0x49, 0x6b, 0x53, 0x7a, 0x51, 0x53, 0x57, 0x38,
			0x61, 0x77, 0x64, 0x57, 0x4a, 0x35, 0x64, 0x2b, 0x31, 0x44, 0x45, 0x4a, 0x52, 0x55, 0x51, 0x3d,
			0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52,
			0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
		}, nil},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := (&Options{SigningKey: tc.input}).GetSigningKey()
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.output, output)

			dir := t.TempDir()
			err = os.WriteFile(filepath.Join(dir, "cert"), []byte(tc.input), 0o0666)
			assert.NoError(t, err)

			output, err = (&Options{SigningKeyFile: filepath.Join(dir, "cert")}).GetSigningKey()
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.output, output)
		})
	}
}

func TestOptions_GetCookieSecret(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		o := NewDefaultOptions()
		bs, err := o.GetCookieSecret()
		assert.NoError(t, err)
		assert.Equal(t, randomSharedKey, base64.StdEncoding.EncodeToString(bs))
	})
	t.Run("missing", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Services = ServiceProxy
		_, err := o.GetCookieSecret()
		assert.Error(t, err)
	})
}

func encodeCert(cert *tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []WeightedURL {
	wu, err := ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
