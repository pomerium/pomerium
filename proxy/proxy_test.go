package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
)

func TestOptionsFromEnvConfig(t *testing.T) {
	tests := []struct {
		name     string
		want     *Options
		envKey   string
		envValue string
		wantErr  bool
	}{
		{"good default, no env settings", defaultOptions, "", "", false},
		{"bad url", nil, "AUTHENTICATE_SERVICE_URL", "%.rjlw", true},
		{"good duration", defaultOptions, "SESSION_VALID_TTL", "1m", false},
		{"bad duration", nil, "SESSION_VALID_TTL", "1sm", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envKey != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}
			got, err := OptionsFromEnvConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("OptionsFromEnvConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OptionsFromEnvConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_urlParse(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    *url.URL
		wantErr bool
	}{
		{"good url without schema", "accounts.google.com", &url.URL{Scheme: "https", Host: "accounts.google.com"}, false},
		{"good url with schema", "https://accounts.google.com", &url.URL{Scheme: "https", Host: "accounts.google.com"}, false},
		{"bad url, malformed", "https://accounts.google.^", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := urlParse(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("urlParse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("urlParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewReverseProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		hostname, _, _ := net.SplitHostPort(r.Host)
		w.Write([]byte(hostname))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	backendHost := net.JoinHostPort(backendHostname, backendPort)
	proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")

	proxyHandler := NewReverseProxy(proxyURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func TestNewReverseProxyHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		hostname, _, _ := net.SplitHostPort(r.Host)
		w.Write([]byte(hostname))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	backendHost := net.JoinHostPort(backendHostname, backendPort)
	proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")

	proxyHandler := NewReverseProxy(proxyURL)
	opts := defaultOptions
	handle := NewReverseProxyHandler(opts, proxyHandler, "name")

	frontend := httptest.NewServer(handle)

	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)

	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func testOptions() *Options {
	authurl, _ := url.Parse("https://sso-auth.corp.beyondperimeter.com")
	return &Options{
		Routes:                 map[string]string{"corp.example.com": "example.com"},
		AuthenticateServiceURL: authurl,
		SharedKey:              "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
		CookieSecret:           "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw=",
	}
}

func TestOptions_Validate(t *testing.T) {
	good := testOptions()
	badFromRoute := testOptions()
	badFromRoute.Routes = map[string]string{"example.com": "^"}
	badToRoute := testOptions()
	badToRoute.Routes = map[string]string{"^": "example.com"}
	badAuthURL := testOptions()
	badAuthURL.AuthenticateServiceURL = nil
	authurl, _ := url.Parse("http://sso-auth.corp.beyondperimeter.com")
	httpAuthURL := testOptions()
	httpAuthURL.AuthenticateServiceURL = authurl
	emptyCookieSecret := testOptions()
	emptyCookieSecret.CookieSecret = ""
	invalidCookieSecret := testOptions()
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := testOptions()
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="

	badSharedKey := testOptions()
	badSharedKey.SharedKey = ""

	tests := []struct {
		name    string
		o       *Options
		wantErr bool
	}{
		{"good - minimum options", good, false},

		{"nil options", &Options{}, true},
		{"from route", badFromRoute, true},
		{"to route", badToRoute, true},
		{"auth service url", badAuthURL, true},
		{"auth service url not https", httpAuthURL, true},
		{"no cookie secret", emptyCookieSecret, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.o
			if err := o.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewProxy(t *testing.T) {
	good := testOptions()
	shortCookieLength := testOptions()
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="

	tests := []struct {
		name      string
		opts      *Options
		optFuncs  []func(*Proxy) error
		wantProxy bool
		numMuxes  int
		wantErr   bool
	}{
		{"good - minimum options", good, nil, true, 1, false},
		{"bad - empty options", &Options{}, nil, false, 0, true},
		{"bad - nil options", nil, nil, false, 0, true},
		{"bad - short secret/validate sanity check", shortCookieLength, nil, false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProxy(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProxy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && tt.wantProxy == true {
				t.Errorf("NewProxy() expected valid proxy struct")
			}
			if got != nil && len(got.mux) != tt.numMuxes {
				t.Errorf("NewProxy() = num muxes %v, want %v", got, tt.numMuxes)
			}
		})
	}
}
