package config

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"math/big"
	mathrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/identity/oauth/apple"
	"github.com/pomerium/protoutil/protorand"
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
	missingStorageDSN.DataBrokerStorageType = "postgres"
	badSignoutRedirectURL := testOptions()
	badSignoutRedirectURL.SignOutRedirectURLString = "--"
	badCookieSettings := testOptions()
	badCookieSettings.CookieSameSite = "none"

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
	t.Setenv("POMERIUM_DEBUG", "true")
	t.Setenv("POLICY", "LSBmcm9tOiBodHRwczovL2h0dHBiaW4ubG9jYWxob3N0LnBvbWVyaXVtLmlvCiAgdG86IAogICAgLSBodHRwOi8vbG9jYWxob3N0OjgwODEsMQo=")
	t.Setenv("HEADERS", `{"X-Custom-1":"foo", "X-Custom-2":"bar"}`)
	err := bindEnvs(v)
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

type Foo struct {
	FieldOne Bar    `mapstructure:"field_one"`
	FieldTwo string `mapstructure:"field_two"`
}
type Bar struct {
	Baz  int    `mapstructure:"baz"`
	Quux string `mapstructure:"quux"`
}

func Test_bindEnvsRecursive(t *testing.T) {
	v := viper.New()
	_, err := bindEnvsRecursive(reflect.TypeOf(Foo{}), v, "", "")
	require.NoError(t, err)

	t.Setenv("FIELD_ONE_BAZ", "123")
	t.Setenv("FIELD_ONE_QUUX", "hello")
	t.Setenv("FIELD_TWO", "world")

	var foo Foo
	v.Unmarshal(&foo)
	assert.Equal(t, Foo{
		FieldOne: Bar{
			Baz:  123,
			Quux: "hello",
		},
		FieldTwo: "world",
	}, foo)
}

func Test_bindEnvsRecursive_Override(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.ReadConfig(strings.NewReader(`
field_one:
  baz: 10
  quux: abc
field_two: hello
`))

	// Baseline: values populated from config file.
	var foo1 Foo
	v.Unmarshal(&foo1)
	assert.Equal(t, Foo{
		FieldOne: Bar{
			Baz:  10,
			Quux: "abc",
		},
		FieldTwo: "hello",
	}, foo1)

	_, err := bindEnvsRecursive(reflect.TypeOf(Foo{}), v, "", "")
	require.NoError(t, err)

	// Environment variables should selectively override config file keys.
	t.Setenv("FIELD_ONE_QUUX", "def")
	var foo2 Foo
	v.Unmarshal(&foo2)
	assert.Equal(t, Foo{
		FieldOne: Bar{
			Baz:  10,
			Quux: "def",
		},
		FieldTwo: "hello",
	}, foo2)

	t.Setenv("FIELD_TWO", "world")
	var foo3 Foo
	v.Unmarshal(&foo3)
	assert.Equal(t, Foo{
		FieldOne: Bar{
			Baz:  10,
			Quux: "def",
		},
		FieldTwo: "world",
	}, foo3)
}

func Test_parseHeaders(t *testing.T) {
	// t.Parallel()
	tests := []struct {
		name         string
		want         map[string]string
		envHeaders   string
		viperHeaders any
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
				From: source,
				To:   []WeightedURL{*to},
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

func Test_decodeSANMatcher(t *testing.T) {
	// Verify that config file parsing will decode the SANMatcher type.
	const yaml = `
downstream_mtls:
  match_subject_alt_names:
    - dns: 'example-1\..*'
    - dns: '.*\.example-2'
`
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(cfg, []byte(yaml), 0o644)
	require.NoError(t, err)

	o, err := optionsFromViper(cfg)
	require.NoError(t, err)

	assert.Equal(t, []SANMatcher{
		{Type: SANTypeDNS, Pattern: `example-1\..*`},
		{Type: SANTypeDNS, Pattern: `.*\.example-2`},
	}, o.DownstreamMTLS.MatchSubjectAltNames)
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
		cmpopts.IgnoreFields(Options{}, "CookieSecret", "GRPCInsecure", "GRPCAddr", "DataBrokerURLString", "DataBrokerURLStrings", "AuthorizeURLString", "AuthorizeURLStrings", "DefaultUpstreamTimeout", "CookieExpire", "Services", "Addr", "LogLevel", "KeyFile", "CertFile", "SharedKey", "ReadTimeout", "IdleTimeout", "GRPCClientTimeout", "TracingSampleRate", "ProgrammaticRedirectDomainWhitelist", "RuntimeFlags"),
		cmpopts.IgnoreFields(Policy{}, "EnvoyOpts"),
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
				CookieHTTPOnly:           true,
				InsecureServer:           true,
				SetResponseHeaders:       map[string]string{"disable": "true"},
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
		{"good client ca file", map[string]string{"DOWNSTREAM_MTLS_CA_FILE": "./testdata/ca.pem", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, false},
		{"bad client ca file", map[string]string{"DOWNSTREAM_MTLS_CA_FILE": "./testdata/bad-ca.pem", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
		{"bad client ca b64", map[string]string{"DOWNSTREAM_MTLS_CA": "bad cert", "INSECURE_SERVER": "true", "SHARED_SECRET": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="}, true},
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
		"ok/simple": func(_ *testing.T) test {
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

	tests := []struct {
		name             string
		certificateFiles []certificateFilePair
		wantErr          bool
	}{
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

func TestHasAnyDownstreamMTLSClientCA(t *testing.T) {
	t.Parallel()

	cases := []struct {
		label    string
		opts     *Options
		expected bool
	}{
		{"zero", &Options{}, false},
		{"default", NewDefaultOptions(), false},
		{"no client CAs", &Options{
			Policies: []Policy{
				{From: "https://example.com/one"},
				{From: "https://example.com/two"},
				{From: "https://example.com/three"},
			},
		}, false},
		{"global client CA only", &Options{
			DownstreamMTLS: DownstreamMTLSSettings{CA: "ZmFrZSBDQQ=="},
			Policies: []Policy{
				{From: "https://example.com/one"},
				{From: "https://example.com/two"},
				{From: "https://example.com/three"},
			},
		}, true},
		{"per-route CA only", &Options{
			Policies: []Policy{
				{From: "https://example.com/one"},
				{
					From:                  "https://example.com/two",
					TLSDownstreamClientCA: "ZmFrZSBDQQ==",
				},
				{From: "https://example.com/three"},
			},
		}, true},
		{"both global and per-route client CAs", &Options{
			DownstreamMTLS: DownstreamMTLSSettings{CA: "ZmFrZSBDQQ=="},
			Policies: []Policy{
				{From: "https://example.com/one"},
				{
					From:                  "https://example.com/two",
					TLSDownstreamClientCA: "ZmFrZSBDQQ==",
				},
				{From: "https://example.com/three"},
			},
		}, true},
	}
	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			actual := c.opts.HasAnyDownstreamMTLSClientCA()
			assert.Equal(t, c.expected, actual)
		})
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
		{"default authenticate url", defaultOptions.GetAuthenticateURL, "https://authenticate.pomerium.app"},
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

func TestOptions_UseStatelessAuthenticateFlow(t *testing.T) {
	t.Run("enabled by default", func(t *testing.T) {
		options := &Options{}
		assert.True(t, options.UseStatelessAuthenticateFlow())
	})
	t.Run("enabled explicitly", func(t *testing.T) {
		options := &Options{AuthenticateURLString: "https://authenticate.pomerium.app"}
		assert.True(t, options.UseStatelessAuthenticateFlow())
	})
	t.Run("disabled", func(t *testing.T) {
		options := &Options{AuthenticateURLString: "https://authenticate.example.com"}
		assert.False(t, options.UseStatelessAuthenticateFlow())
	})
	t.Run("force enabled", func(t *testing.T) {
		options := &Options{AuthenticateURLString: "https://authenticate.example.com"}
		t.Setenv("DEBUG_FORCE_AUTHENTICATE_FLOW", "stateless")
		assert.True(t, options.UseStatelessAuthenticateFlow())
	})
	t.Run("force disabled", func(t *testing.T) {
		options := &Options{}
		t.Setenv("DEBUG_FORCE_AUTHENTICATE_FLOW", "stateful")
		assert.False(t, options.UseStatelessAuthenticateFlow())
	})
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
		cert1path := filepath.Join(t.TempDir(), "example.com.pem")
		err = os.WriteFile(cert1path, cert1.Certificate[0], 0o600)
		require.NoError(t, err)
		options.CertificateFiles = append(options.CertificateFiles, certificateFilePair{
			CertFile: cert1path,
		})
		cert2, err := cryptutil.GenerateCertificate(nil, "example.com")
		require.NoError(t, err)
		cert3, err := cryptutil.GenerateCertificate(nil, "not.example.com")
		require.NoError(t, err)

		certsIndex := cryptutil.NewCertificatesIndex()
		xc1, _ := x509.ParseCertificate(cert1.Certificate[0])
		certsIndex.Add(xc1)

		settings := &configpb.Settings{
			Certificates: []*configpb.Settings_Certificate{
				{CertBytes: encodeCert(cert2)},
				{CertBytes: encodeCert(cert3)},
			},
		}
		options.ApplySettings(ctx, certsIndex, settings)
		assert.Len(t, options.CertificateData, 1, "should prevent adding duplicate certificates")
	})

	t.Run("pass_identity_headers", func(t *testing.T) {
		options := NewDefaultOptions()
		options.ApplySettings(ctx, nil, &configpb.Settings{
			PassIdentityHeaders: proto.Bool(true),
		})
		assert.Equal(t, proto.Bool(true), options.PassIdentityHeaders)
	})

	t.Run("branding", func(t *testing.T) {
		options := NewDefaultOptions()
		options.ApplySettings(ctx, nil, &configpb.Settings{
			PrimaryColor: proto.String("#FFFFFF"),
		})
		options.ApplySettings(ctx, nil, &configpb.Settings{})
		assert.Equal(t, "#FFFFFF", options.BrandingOptions.GetPrimaryColor())
		options.ApplySettings(ctx, nil, &configpb.Settings{
			PrimaryColor: proto.String("#333333"),
		})
		assert.Equal(t, "#333333", options.BrandingOptions.GetPrimaryColor())
	})

	t.Run("jwt_groups_filter", func(t *testing.T) {
		options := NewDefaultOptions()
		options.ApplySettings(ctx, nil, &configpb.Settings{
			JwtGroupsFilter: []string{"foo", "bar", "baz"},
		})
		options.ApplySettings(ctx, nil, &configpb.Settings{})
		assert.Equal(t, NewJWTGroupsFilter([]string{"foo", "bar", "baz"}), options.JWTGroupsFilter)
		options.ApplySettings(ctx, nil, &configpb.Settings{
			JwtGroupsFilter: []string{"quux", "zulu"},
		})
		assert.Equal(t, NewJWTGroupsFilter([]string{"quux", "zulu"}), options.JWTGroupsFilter)
	})
}

func TestXXX(t *testing.T) {
	dir, _ := os.MkdirTemp("", "asdf")
	t.Log(dir)
	for i := 1; i <= 100; i++ {
		crt, _ := cryptutil.GenerateCertificate(nil, fmt.Sprintf("route%d.localhost.pomerium.io", i))
		crtBytes, keyBytes, _ := cryptutil.EncodeCertificate(crt)
		os.WriteFile(fmt.Sprintf("%s/%d.crt", dir, i), crtBytes, 0o644)
		os.WriteFile(fmt.Sprintf("%s/%d.key", dir, i), keyBytes, 0o600)
	}
}

func TestOptions_GetSetResponseHeaders(t *testing.T) {
	t.Run("lax", func(t *testing.T) {
		options := NewDefaultOptions()
		assert.Equal(t, map[string]string{
			"X-Frame-Options":  "SAMEORIGIN",
			"X-XSS-Protection": "1; mode=block",
		}, options.GetSetResponseHeaders())
	})
	t.Run("strict", func(t *testing.T) {
		options := NewDefaultOptions()
		options.Cert = "CERT"
		assert.Equal(t, map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			"X-Frame-Options":           "SAMEORIGIN",
			"X-XSS-Protection":          "1; mode=block",
		}, options.GetSetResponseHeaders())
	})
	t.Run("autocert-staging", func(t *testing.T) {
		options := NewDefaultOptions()
		options.Cert = "CERT"
		options.AutocertOptions.UseStaging = true
		assert.Equal(t, map[string]string{
			"X-Frame-Options":  "SAMEORIGIN",
			"X-XSS-Protection": "1; mode=block",
		}, options.GetSetResponseHeaders())
	})
	t.Run("disable", func(t *testing.T) {
		options := NewDefaultOptions()
		options.SetResponseHeaders = map[string]string{DisableHeaderKey: "1", "x-other": "xyz"}
		assert.Equal(t, map[string]string{}, options.GetSetResponseHeaders())
	})
	t.Run("empty", func(t *testing.T) {
		options := NewDefaultOptions()
		options.SetResponseHeaders = map[string]string{}
		assert.Equal(t, map[string]string{}, options.GetSetResponseHeaders())
	})
	t.Run("no partial defaults", func(t *testing.T) {
		options := NewDefaultOptions()
		options.Cert = "CERT"
		options.SetResponseHeaders = map[string]string{"X-Frame-Options": "DENY"}
		assert.Equal(t, map[string]string{"X-Frame-Options": "DENY"},
			options.GetSetResponseHeaders())
	})
}

func TestOptions_GetSetResponseHeadersForPolicy(t *testing.T) {
	t.Run("disable but set in policy", func(t *testing.T) {
		options := NewDefaultOptions()
		options.SetResponseHeaders = map[string]string{DisableHeaderKey: "1"}
		policy := &Policy{
			SetResponseHeaders: map[string]string{"x": "y"},
		}
		assert.Equal(t, map[string]string{"x": "y"}, options.GetSetResponseHeadersForPolicy(policy))
	})
	t.Run("global defaults plus policy", func(t *testing.T) {
		options := NewDefaultOptions()
		options.Cert = "CERT"
		policy := &Policy{
			SetResponseHeaders: map[string]string{"Route": "xyz"},
		}
		assert.Equal(t, map[string]string{
			"Route":                     "xyz",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			"X-Frame-Options":           "SAMEORIGIN",
			"X-XSS-Protection":          "1; mode=block",
		}, options.GetSetResponseHeadersForPolicy(policy))
	})
	t.Run("global defaults partial override", func(t *testing.T) {
		options := NewDefaultOptions()
		options.Cert = "CERT"
		policy := &Policy{
			SetResponseHeaders: map[string]string{"X-Frame-Options": "DENY"},
		}
		assert.Equal(t, map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			"X-Frame-Options":           "DENY",
			"X-XSS-Protection":          "1; mode=block",
		}, options.GetSetResponseHeadersForPolicy(policy))
	})
	t.Run("multiple policies", func(t *testing.T) {
		options := NewDefaultOptions()
		options.SetResponseHeaders = map[string]string{"global": "foo"}
		p1 := &Policy{
			SetResponseHeaders: map[string]string{"route-1": "bar"},
		}
		p2 := &Policy{
			SetResponseHeaders: map[string]string{"route-2": "baz"},
		}
		assert.Equal(t, map[string]string{
			"global":  "foo",
			"route-1": "bar",
		}, options.GetSetResponseHeadersForPolicy(p1))
		assert.Equal(t, map[string]string{
			"global":  "foo",
			"route-2": "baz",
		}, options.GetSetResponseHeadersForPolicy(p2))
		assert.Equal(t, map[string]string{"global": "foo"}, options.GetSetResponseHeaders())
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

func TestOptions_GetCookieSameSite(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input    string
		expected http.SameSite
	}{
		{"", http.SameSiteDefaultMode},
		{"Lax", http.SameSiteLaxMode},
		{"lax", http.SameSiteLaxMode},
		{"Strict", http.SameSiteStrictMode},
		{"strict", http.SameSiteStrictMode},
		{"None", http.SameSiteNoneMode},
		{"none", http.SameSiteNoneMode},
		{"UnKnOwN", http.SameSiteDefaultMode},
	} {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			o := NewDefaultOptions()
			o.CookieSameSite = tc.input
			assert.Equal(t, tc.expected, o.GetCookieSameSite())
		})
	}
}

func TestOptions_GetCSRFSameSite(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		cookieSameSite string
		provider       string
		expected       csrf.SameSiteMode
	}{
		{"", "", csrf.SameSiteDefaultMode},
		{"Lax", "", csrf.SameSiteLaxMode},
		{"lax", "", csrf.SameSiteLaxMode},
		{"Strict", "", csrf.SameSiteStrictMode},
		{"strict", "", csrf.SameSiteStrictMode},
		{"None", "", csrf.SameSiteNoneMode},
		{"none", "", csrf.SameSiteNoneMode},
		{"UnKnOwN", "", csrf.SameSiteDefaultMode},
		{"", apple.Name, csrf.SameSiteNoneMode},
	} {
		tc := tc
		t.Run(tc.cookieSameSite, func(t *testing.T) {
			t.Parallel()

			o := NewDefaultOptions()
			o.CookieSameSite = tc.cookieSameSite
			o.Provider = tc.provider
			assert.Equal(t, tc.expected, o.GetCSRFSameSite())
		})
	}
}

func TestOptions_RequestParams(t *testing.T) {
	cases := []struct {
		label    string
		config   string
		expected map[string]string
	}{
		{"not present", "", nil},
		{"explicitly empty", "idp_request_params: {}", map[string]string{}},
	}
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	for i := range cases {
		c := &cases[i]
		t.Run(c.label, func(t *testing.T) {
			err := os.WriteFile(cfg, []byte(c.config), 0o644)
			require.NoError(t, err)
			o, err := newOptionsFromConfig(cfg)
			require.NoError(t, err)
			assert.Equal(t, c.expected, o.RequestParams)
		})
	}
}

func TestOptions_RequestParamsFromEnv(t *testing.T) {
	t.Setenv("IDP_REQUEST_PARAMS", `{"x":"y"}`)

	options, err := newOptionsFromConfig("")
	if assert.NoError(t, err) {
		assert.Equal(t, map[string]string{"x": "y"}, options.RequestParams)
	}
}

func TestOptions_RuntimeFlags(t *testing.T) {
	t.Parallel()

	extra := DefaultRuntimeFlags()
	extra["another"] = true

	cases := []struct {
		label    string
		config   string
		expected RuntimeFlags
	}{
		{"not present", "", DefaultRuntimeFlags()},
		{"explicitly empty", `{"runtime_flags": {}}`, DefaultRuntimeFlags()},
		{"all", `{"runtime_flags":{"another":true}}`, extra},
	}
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			err := os.WriteFile(cfg, []byte(c.config), 0o644)
			require.NoError(t, err)
			o, err := newOptionsFromConfig(cfg)
			require.NoError(t, err)
			assert.Equal(t, c.expected, o.RuntimeFlags)
		})
	}
}

func TestOptions_GetDataBrokerStorageConnectionString(t *testing.T) {
	t.Parallel()

	t.Run("validate", func(t *testing.T) {
		t.Parallel()

		o := NewDefaultOptions()
		o.Services = "databroker"
		o.DataBrokerStorageType = "postgres"
		o.SharedKey = cryptutil.NewBase64Key()

		assert.ErrorContains(t, o.Validate(), "missing databroker storage backend dsn",
			"should validate DSN")

		o.DataBrokerStorageConnectionString = "DSN"
		assert.NoError(t, o.Validate(),
			"should have no error when the dsn is set")

		o.DataBrokerStorageConnectionString = ""
		o.DataBrokerStorageConnectionStringFile = "DSN_FILE"
		assert.NoError(t, o.Validate(),
			"should have no error when the dsn file is set")
	})
	t.Run("literal", func(t *testing.T) {
		t.Parallel()

		o := NewDefaultOptions()
		o.DataBrokerStorageConnectionString = "DSN"

		dsn, err := o.GetDataBrokerStorageConnectionString()
		assert.NoError(t, err)
		assert.Equal(t, "DSN", dsn)
	})
	t.Run("file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		fp := filepath.Join(dir, "DSN_FILE")

		o := NewDefaultOptions()
		o.DataBrokerStorageConnectionStringFile = fp
		o.DataBrokerStorageConnectionString = "IGNORED"

		dsn, err := o.GetDataBrokerStorageConnectionString()
		assert.Error(t, err,
			"should return an error when the file doesn't exist")
		assert.Empty(t, dsn)

		os.WriteFile(fp, []byte(`
			DSN
		`), 0o644)

		dsn, err = o.GetDataBrokerStorageConnectionString()
		assert.NoError(t, err,
			"should not return an error when the file exists")
		assert.Equal(t, "DSN", dsn,
			"should return the trimmed contents of the file")
	})
}

func encodeCert(cert *tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func TestRoute_FromToProto(t *testing.T) {
	routeGen := protorand.New[*configpb.Route]()
	routeGen.MaxCollectionElements = 2
	routeGen.UseGoDurationLimits = true
	routeGen.ExcludeMask(&fieldmaskpb.FieldMask{
		Paths: []string{
			"from", "to", "load_balancing_weights", "redirect", "response", // set below
			"ppl_policies", "name", // no equivalent field
			"envoy_opts",
		},
	})
	redirectGen := protorand.New[*configpb.RouteRedirect]()
	responseGen := protorand.New[*configpb.RouteDirectResponse]()

	randomDomain := func() string {
		numSegments := mathrand.IntN(5) + 1
		segments := make([]string, numSegments)
		for i := range segments {
			b := make([]rune, mathrand.IntN(10)+10)
			for j := range b {
				b[j] = rune(mathrand.IntN(26) + 'a')
			}
			segments[i] = string(b)
		}
		return strings.Join(segments, ".")
	}

	newCompleteRoute := func() *configpb.Route {
		pb, err := routeGen.Gen()

		require.NoError(t, err)
		pb.From = "https://" + randomDomain()
		// EnvoyOpts is set to an empty non-nil message during conversion, if nil
		pb.EnvoyOpts = &envoy_config_cluster_v3.Cluster{}
		// JWT groups filter order is not significant. Upon conversion back to
		// a protobuf the JWT groups will be sorted.
		slices.Sort(pb.JwtGroupsFilter)

		switch mathrand.IntN(3) {
		case 0:
			pb.To = make([]string, mathrand.IntN(3)+1)
			for i := range pb.To {
				pb.To[i] = "https://" + randomDomain()
			}
			pb.LoadBalancingWeights = make([]uint32, len(pb.To))
			for i := range pb.LoadBalancingWeights {
				pb.LoadBalancingWeights[i] = mathrand.Uint32N(10000) + 1
			}
		case 1:
			pb.Redirect, err = redirectGen.Gen()
			require.NoError(t, err)
		case 2:
			pb.Response, err = responseGen.Gen()
			require.NoError(t, err)
		}
		return pb
	}

	t.Run("Round Trip", func(t *testing.T) {
		for range 100 {
			route := newCompleteRoute()

			policy, err := NewPolicyFromProto(route)
			require.NoError(t, err)

			route2, err := policy.ToProto()
			require.NoError(t, err)
			route2.Name = ""

			testutil.AssertProtoEqual(t, route, route2)
		}
	})

	t.Run("Multiple routes", func(t *testing.T) {
		for range 100 {
			route1 := newCompleteRoute()
			route2 := newCompleteRoute()

			{
				// create a new policy every time, since reusing the target will mutate
				// the underlying route
				policy1, err := NewPolicyFromProto(route1)
				require.NoError(t, err)
				target, err := policy1.ToProto()
				require.NoError(t, err)
				target.Name = ""
				testutil.AssertProtoEqual(t, route1, target)
			}
			{
				policy2, err := NewPolicyFromProto(route2)
				require.NoError(t, err)
				target, err := policy2.ToProto()
				require.NoError(t, err)
				target.Name = ""
				testutil.AssertProtoEqual(t, route2, target)
			}
			{
				policy1, err := NewPolicyFromProto(route1)
				require.NoError(t, err)
				target, err := policy1.ToProto()
				require.NoError(t, err)
				target.Name = ""
				testutil.AssertProtoEqual(t, route1, target)
			}
			{
				policy2, err := NewPolicyFromProto(route2)
				require.NoError(t, err)
				target, err := policy2.ToProto()
				require.NoError(t, err)
				target.Name = ""
				testutil.AssertProtoEqual(t, route2, target)
			}
		}
	})
}

func TestOptions_FromToProto(t *testing.T) {
	generate := func(ratio float64) *configpb.Settings {
		t.Helper()
		gen := protorand.New[*configpb.Settings]()
		gen.MaxCollectionElements = 2
		gen.MaxDepth = 3
		gen.UseGoDurationLimits = true
		gen.ExcludeMask(&fieldmaskpb.FieldMask{
			Paths: []string{
				"tls_custom_ca_file",
				"tls_client_cert_file",
				"tls_client_key_file",
				"tls_downstream_client_ca_file",
			},
		})

		settings, err := gen.GenPartial(ratio)
		require.NoError(t, err)
		unsetFalseOptionalBoolFields(settings)
		fixZeroValuedEnums(settings)
		generateCertificates(t, settings)
		// JWT groups filter order is not significant. Upon conversion back to
		// a protobuf the JWT groups will be sorted.
		slices.Sort(settings.JwtGroupsFilter)

		return settings
	}

	t.Run("all fields", func(t *testing.T) {
		t.Parallel()
		for range 100 {
			settings := generate(1)
			var options Options
			options.ApplySettings(context.Background(), nil, settings)
			settings2 := options.ToProto()
			testutil.AssertProtoEqual(t, settings, settings2.Settings)
		}
	})

	t.Run("some fields", func(t *testing.T) {
		t.Parallel()
		for range 100 {
			settings := generate(mathrand.Float64())
			var options Options
			options.ApplySettings(context.Background(), nil, settings)
			settings2 := options.ToProto()
			testutil.AssertProtoEqual(t, settings, settings2.Settings)
		}
	})
}

// unset any optional bool fields with a value of false, to match
func unsetFalseOptionalBoolFields(msg proto.Message) {
	msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Cardinality() == protoreflect.Optional && fd.Kind() == protoreflect.BoolKind {
			if v.IsValid() && !v.Bool() {
				msg.ProtoReflect().Clear(fd)
			}
		}
		return true
	})
}

func fixZeroValuedEnums(msg *configpb.Settings) {
	if msg.DownstreamMtls != nil && msg.DownstreamMtls.Enforcement != nil {
		// there is no "unknown" equivalent, so if the value is randomly set to
		// unknown it would be a lossy conversion
		if *msg.DownstreamMtls.Enforcement == configpb.MtlsEnforcementMode_UNKNOWN {
			msg.DownstreamMtls.Enforcement = nil
			// if this was the only present field in the message, don't leave it empty
			if proto.Size(msg.DownstreamMtls) == 0 {
				msg.DownstreamMtls = nil
			}
		}
	}
}

func generateCertificates(t testing.TB, msg *configpb.Settings) {
	if msg.AutocertCa != nil {
		*msg.AutocertCa, _ = generateRandomCA(t, *msg.AutocertCa)
	}
	if msg.DownstreamMtls != nil {
		var caKey string
		if msg.DownstreamMtls.Ca != nil {
			*msg.DownstreamMtls.Ca, caKey = generateRandomCA(t, *msg.DownstreamMtls.Ca)
		}
		if msg.DownstreamMtls.Crl != nil {
			if caKey != "" {
				*msg.DownstreamMtls.Crl = generateCRL(t, *msg.DownstreamMtls.Crl, *msg.DownstreamMtls.Ca, caKey)
			} else {
				randCa, randKey := generateRandomCA(t, *msg.DownstreamMtls.Crl+"_temp_ca")
				*msg.DownstreamMtls.Crl = generateCRL(t, *msg.DownstreamMtls.Crl, randCa, randKey)
			}
		}
	}
	genCertInPlace := func(cert *configpb.Settings_Certificate, b64 bool) {
		cert.Id = "" // no equivalent field
		switch {
		case len(cert.CertBytes) > 0 && len(cert.KeyBytes) > 0:
			crt, key := generateRandomCert(t, string(cert.CertBytes)+string(cert.KeyBytes), b64)
			cert.CertBytes = []byte(crt)
			cert.KeyBytes = []byte(key)
		case len(cert.CertBytes) > 0 && len(cert.KeyBytes) == 0:
			crt, _ := generateRandomCert(t, string(cert.CertBytes), b64)
			cert.CertBytes = []byte(crt)
		case len(cert.CertBytes) == 0 && len(cert.KeyBytes) > 0:
			// invalid, but convert anyway
			crt, _ := generateRandomCert(t, string(cert.KeyBytes), b64)
			cert.KeyBytes = []byte(crt)
		}
	}
	for i, cert := range msg.Certificates {
		genCertInPlace(cert, false)
		if cert.CertBytes == nil && cert.KeyBytes == nil {
			msg.Certificates = slices.Delete(msg.Certificates, i, i+1)
		}
	}
	if msg.MetricsCertificate != nil {
		genCertInPlace(msg.MetricsCertificate, false)
		if msg.MetricsCertificate.CertBytes == nil && msg.MetricsCertificate.KeyBytes == nil {
			msg.MetricsCertificate = nil
		}
	}
}

func generateRandomCA(t testing.TB, randomInput string) (string, string) {
	seed := sha256.Sum256([]byte(randomInput))
	priv := ed25519.NewKeyFromSeed(seed[:])
	h := fnv.New128()
	h.Write([]byte(randomInput))
	sum := h.Sum(nil)
	var sn big.Int
	sn.SetBytes(sum)

	now := time.Now()
	tmpl := &x509.Certificate{
		IsCA:         true,
		SerialNumber: &sn,
		Subject:      pkix.Name{CommonName: randomInput},
		Issuer:       pkix.Name{CommonName: randomInput},
		NotBefore:    now,
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})), base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: must(x509.MarshalPKCS8PrivateKey(priv)),
		}))
}

func generateCRL(t testing.TB, randomInput string, issuerCrt, issuerKey string) string {
	h := fnv.New128()
	h.Write([]byte(randomInput))
	sum := h.Sum(nil)
	var sn big.Int
	sn.SetBytes(sum)
	issuer, err := cryptutil.CertificateFromBase64(issuerCrt, issuerKey)
	require.NoError(t, err)
	b, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(0x2000),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   &sn,
				RevocationTime: time.Now(),
			},
		},
	}, issuer.Leaf, issuer.PrivateKey.(crypto.Signer))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

func generateRandomCert(t testing.TB, randomInput string, b64 bool) (string, string) {
	seed := sha256.Sum256([]byte(randomInput))
	priv := ed25519.NewKeyFromSeed(seed[:])
	h := fnv.New128()
	h.Write([]byte(randomInput))
	sum := h.Sum(nil)
	var sn big.Int
	sn.SetBytes(sum)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: &sn,
		Subject: pkix.Name{
			CommonName: randomInput,
		},
		Issuer: pkix.Name{
			CommonName: randomInput,
		},
		NotBefore: now,
		NotAfter:  now.Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	crtPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: must(x509.MarshalPKCS8PrivateKey(priv)),
	})
	if b64 {
		return base64.StdEncoding.EncodeToString(crtPem), base64.StdEncoding.EncodeToString(keyPem)
	}
	return string(crtPem), string(keyPem)
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
