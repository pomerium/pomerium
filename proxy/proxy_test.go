package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/config"

	"github.com/pomerium/pomerium/internal/policy"
)

var fixedDate = time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

func TestNewReverseProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
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
		w.WriteHeader(http.StatusOK)
		hostname, _, _ := net.SplitHostPort(r.Host)
		w.Write([]byte(hostname))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	backendHost := net.JoinHostPort(backendHostname, backendPort)
	proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")
	proxyHandler := NewReverseProxy(proxyURL)
	opts := config.NewOptions()
	opts.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU0zbXBaSVdYQ1g5eUVneFU2czU3Q2J0YlVOREJTQ0VBdFFGNWZVV0hwY1FvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFaFBRditMQUNQVk5tQlRLMHhTVHpicEVQa1JyazFlVXQxQk9hMzJTRWZVUHpOaTRJV2VaLwpLS0lUdDJxMUlxcFYyS01TYlZEeXI5aWp2L1hoOThpeUV3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	route, err := policy.FromConfig([]byte(`[{"from":"corp.example.com","to":"example.com","timeout":"1s"}]`))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := NewReverseProxyHandler(opts, proxyHandler, &route[0])
	if err != nil {
		t.Errorf("got %q", err)
	}

	frontend := httptest.NewServer(handle)

	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)

	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func testOptions() *config.Options {
	authenticateService, _ := url.Parse("https://authenticate.corp.beyondperimeter.com")
	authorizeService, _ := url.Parse("https://authorize.corp.beyondperimeter.com")
	configBlob := `[{"from":"corp.example.notatld","to":"example.notatld"}]`
	policy := base64.URLEncoding.EncodeToString([]byte(configBlob))

	opts := config.NewOptions()
	opts.Policy = policy
	opts.AuthenticateURL = authenticateService
	opts.AuthorizeURL = authorizeService
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	opts.CookieName = "pomerium"
	return opts
}

func testOptionsTestServer(uri string) *config.Options {
	authenticateService, _ := url.Parse("https://authenticate.corp.beyondperimeter.com")
	authorizeService, _ := url.Parse("https://authorize.corp.beyondperimeter.com")
	// RFC 2606
	configBlob := fmt.Sprintf(`[{"from":"httpbin.corp.example","to":"%s"}]`, uri)
	policy := base64.URLEncoding.EncodeToString([]byte(configBlob))

	opts := config.NewOptions()
	opts.Policy = policy
	opts.AuthenticateURL = authenticateService
	opts.AuthorizeURL = authorizeService
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	opts.CookieName = "pomerium"
	return opts
}

func testOptionsWithCORS(uri string) *config.Options {
	configBlob := fmt.Sprintf(`[{"from":"httpbin.corp.example","to":"%s","cors_allow_preflight":true}]`, uri)
	opts := testOptionsTestServer(uri)
	opts.Policy = base64.URLEncoding.EncodeToString([]byte(configBlob))
	return opts
}


func testOptionsWithPublicAccess(uri string) *config.Options {
	configBlob := fmt.Sprintf(`[{"from":"httpbin.corp.example","to":"%s","allow_public_unauthenticated_access":true}]`, uri)
	opts := testOptions()
	opts.Policy = base64.URLEncoding.EncodeToString([]byte(configBlob))
	return opts
}

func testOptionsWithPublicAccessAndWhitelist(uri string) *config.Options {
	configBlob := fmt.Sprintf(`[{"from":"httpbin.corp.example","to":"%s","allow_public_unauthenticated_access":true,"allowed_users":["test@gmail.com"]}]`, uri)
	opts := testOptions()
	opts.Policy = base64.URLEncoding.EncodeToString([]byte(configBlob))
	return opts
}

func TestOptions_Validate(t *testing.T) {
	good := testOptions()
	badFromRoute := testOptions()
	badFromRoute.Routes = map[string]string{"example.com": "^"}
	badToRoute := testOptions()
	badToRoute.Routes = map[string]string{"^": "example.com"}
	badAuthURL := testOptions()
	badAuthURL.AuthenticateURL = nil
	authurl, _ := url.Parse("http://authenticate.corp.beyondperimeter.com")
	authenticateBadScheme := testOptions()
	authenticateBadScheme.AuthenticateURL = authurl
	authorizeBadSCheme := testOptions()
	authorizeBadSCheme.AuthorizeURL = authurl
	authorizeNil := testOptions()
	authorizeNil.AuthorizeURL = nil
	emptyCookieSecret := testOptions()
	emptyCookieSecret.CookieSecret = ""
	invalidCookieSecret := testOptions()
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := testOptions()
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	invalidSignKey := testOptions()
	invalidSignKey.SigningKey = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	badSharedKey := testOptions()
	badSharedKey.SharedKey = ""
	policyBadBase64 := testOptions()
	policyBadBase64.Policy = "^"
	badPolicyToURL := testOptions()
	badPolicyToURL.Policy = "LSBmcm9tOiBodHRwYmluLmNvcnAuYmV5b25kcGVyaW1ldGVyLmNvbQogIHRvOiBodHRwOi8vaHR0cGJpbl4KICBhbGxvd2VkX2RvbWFpbnM6CiAgICAtIHBvbWVyaXVtLmlv"
	badPolicyFromURL := testOptions()
	badPolicyFromURL.Policy = "LSBmcm9tOiBodHRwYmluLmNvcnAuYmV5b25kcGVyaW1ldGVyLmNvbQogIHRvOiBodHRwOi8vaHR0cGJpbl4KICBhbGxvd2VkX2RvbWFpbnM6CiAgICAtIHBvbWVyaXVtLmlv"
	corsPolicy := testOptionsWithCORS("example.notatld")
	publicPolicy := testOptionsWithPublicAccess("example.notatld")
	publicWithWhitelistPolicy := testOptionsWithPublicAccessAndWhitelist("example.notatld")

	tests := []struct {
		name    string
		o       *config.Options
		wantErr bool
	}{
		{"good - minimum options", good, false},
		{"nil options", &config.Options{}, true},
		{"from route", badFromRoute, true},
		{"to route", badToRoute, true},
		{"authenticate service url", badAuthURL, true},
		{"authenticate service url not https", authenticateBadScheme, true},
		{"authorize service url not https", authorizeBadSCheme, true},
		{"authorize service cannot be nil", authorizeNil, true},
		{"no cookie secret", emptyCookieSecret, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
		{"invalid signing key", invalidSignKey, true},
		{"policy invalid base64", policyBadBase64, true},
		{"policy bad to url", badPolicyFromURL, true},
		{"policy bad from url", badPolicyFromURL, true},
		{"CORS policy good", corsPolicy, false},
		{"policy public good", publicPolicy, false},
		{"policy public and whitelist bad", publicWithWhitelistPolicy, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.o
			if err := ValidateOptions(o); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {

	good := testOptions()
	shortCookieLength := testOptions()
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badRoutedProxy := testOptions()
	badRoutedProxy.SigningKey = "YmFkIGtleQo="
	tests := []struct {
		name      string
		opts      *config.Options
		wantProxy bool
		numRoutes int
		wantErr   bool
	}{
		{"good", good, true, 1, false},
		{"empty options", &config.Options{}, false, 0, true},
		{"nil options", nil, false, 0, true},
		{"short secret/validate sanity check", shortCookieLength, false, 0, true},
		{"invalid ec key, valid base64 though", badRoutedProxy, false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && tt.wantProxy == true {
				t.Errorf("New() expected valid proxy struct")
			}
			if got != nil && len(got.routeConfigs) != tt.numRoutes {
				t.Errorf("New() = num routeConfigs \n%+v, want \n%+v", got, tt.numRoutes)
			}
		})
	}
}
