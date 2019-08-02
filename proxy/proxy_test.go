package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/config"
)

var fixedDate = time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

func newTestOptions(t *testing.T) *config.Options {
	opts, err := config.NewOptions("https://authenticate.example", "https://authorize.example")
	if err != nil {
		t.Fatal(err)
	}
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	return opts
}

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
	opts := newTestOptions(t)
	opts.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU0zbXBaSVdYQ1g5eUVneFU2czU3Q2J0YlVOREJTQ0VBdFFGNWZVV0hwY1FvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFaFBRditMQUNQVk5tQlRLMHhTVHpicEVQa1JyazFlVXQxQk9hMzJTRWZVUHpOaTRJV2VaLwpLS0lUdDJxMUlxcFYyS01TYlZEeXI5aWp2L1hoOThpeUV3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	testPolicy := config.Policy{From: "https://corp.example.com", To: "https://example.com", UpstreamTimeout: 1 * time.Second}
	if err := testPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := New(*opts)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := p.newReverseProxyHandler(proxyHandler, &testPolicy)
	if err != nil {
		t.Fatal(err)
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

func testOptions(t *testing.T) config.Options {
	authenticateService, _ := url.Parse("https://authenticate.corp.beyondperimeter.com")
	authorizeService, _ := url.Parse("https://authorize.corp.beyondperimeter.com")

	opts := newTestOptions(t)
	testPolicy := config.Policy{From: "https://corp.example.example", To: "https://example.example"}
	opts.Policies = []config.Policy{testPolicy}
	opts.AuthenticateURL = *authenticateService
	opts.AuthorizeURL = *authorizeService
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	opts.CookieName = "pomerium"
	err := opts.Validate()
	if err != nil {
		t.Fatal(err)
	}
	return *opts
}

func testOptionsTestServer(t *testing.T, uri string) config.Options {
	authenticateService, _ := url.Parse("https://authenticate.corp.beyondperimeter.com")
	authorizeService, _ := url.Parse("https://authorize.corp.beyondperimeter.com")
	testPolicy := config.Policy{
		From: "https://httpbin.corp.example",
		To:   uri,
	}
	if err := testPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	opts := newTestOptions(t)
	opts.Policies = []config.Policy{testPolicy}
	opts.AuthenticateURL = *authenticateService
	opts.AuthorizeURL = *authorizeService
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="
	opts.CookieName = "pomerium"
	return *opts
}

func testOptionsWithCORS(t *testing.T, uri string) config.Options {
	testPolicy := config.Policy{
		From:               "https://httpbin.corp.example",
		To:                 uri,
		CORSAllowPreflight: true,
	}
	if err := testPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	opts := testOptionsTestServer(t, uri)
	opts.Policies = []config.Policy{testPolicy}
	return opts
}

func testOptionsWithPublicAccess(t *testing.T, uri string) config.Options {
	testPolicy := config.Policy{
		From:                             "https://httpbin.corp.example",
		To:                               uri,
		AllowPublicUnauthenticatedAccess: true,
	}
	if err := testPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	opts := testOptions(t)
	opts.Policies = []config.Policy{testPolicy}
	return opts
}

func testOptionsWithEmptyPolicies(t *testing.T, uri string) config.Options {
	opts := testOptionsTestServer(t, uri)
	opts.Policies = []config.Policy{}
	return opts
}

func TestOptions_Validate(t *testing.T) {
	good := testOptions(t)
	badAuthURL := testOptions(t)
	badAuthURL.AuthenticateURL = url.URL{}
	authurl, _ := url.Parse("http://authenticate.corp.beyondperimeter.com")
	authenticateBadScheme := testOptions(t)
	authenticateBadScheme.AuthenticateURL = *authurl
	authorizeBadSCheme := testOptions(t)
	authorizeBadSCheme.AuthorizeURL = *authurl
	authorizeNil := testOptions(t)
	authorizeNil.AuthorizeURL = url.URL{}
	emptyCookieSecret := testOptions(t)
	emptyCookieSecret.CookieSecret = ""
	invalidCookieSecret := testOptions(t)
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := testOptions(t)
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	invalidSignKey := testOptions(t)
	invalidSignKey.SigningKey = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	badSharedKey := testOptions(t)
	badSharedKey.SharedKey = ""
	sharedKeyBadBas64 := testOptions(t)
	sharedKeyBadBas64.SharedKey = "%(*@389"
	missingPolicy := testOptions(t)
	missingPolicy.Policies = []config.Policy{}

	tests := []struct {
		name    string
		o       config.Options
		wantErr bool
	}{
		{"good - minimum options", good, false},
		{"nil options", config.Options{}, true},
		{"authenticate service url", badAuthURL, true},
		{"authenticate service url not https", authenticateBadScheme, true},
		{"authorize service url not https", authorizeBadSCheme, true},
		{"authorize service cannot be nil", authorizeNil, true},
		{"no cookie secret", emptyCookieSecret, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
		{"invalid signing key", invalidSignKey, true},
		{"shared secret bad base64", sharedKeyBadBas64, true},
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

	good := testOptions(t)
	shortCookieLength := testOptions(t)
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badRoutedProxy := testOptions(t)
	badRoutedProxy.SigningKey = "YmFkIGtleQo="
	tests := []struct {
		name      string
		opts      config.Options
		wantProxy bool
		numRoutes int
		wantErr   bool
	}{
		{"good", good, true, 1, false},
		{"empty options", config.Options{}, false, 0, true},
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
				t.Errorf("New() = num routeConfigs \n%+v, want \n%+v \nfrom %+v", got, tt.numRoutes, tt.opts)
			}
		})
	}
}

func Test_UpdateOptions(t *testing.T) {

	good := testOptions(t)
	newPolicy := config.Policy{To: "http://foo.example", From: "http://bar.example"}
	newPolicies := testOptions(t)
	newPolicies.Policies = []config.Policy{
		newPolicy,
	}
	err := newPolicy.Validate()
	if err != nil {
		t.Fatal(err)
	}
	badPolicyURL := config.Policy{To: "http://", From: "http://bar.example"}
	badNewPolicy := testOptions(t)
	badNewPolicy.Policies = []config.Policy{
		badPolicyURL,
	}
	disableTLSPolicy := config.Policy{To: "http://foo.example", From: "http://bar.example", TLSSkipVerify: true}
	disableTLSPolicies := testOptions(t)
	disableTLSPolicies.Policies = []config.Policy{
		disableTLSPolicy,
	}
	customCAPolicy := config.Policy{To: "http://foo.example", From: "http://bar.example", TLSCustomCA: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURlVENDQW1HZ0F3SUJBZ0lKQUszMmhoR0JIcmFtTUEwR0NTcUdTSWIzRFFFQkN3VUFNR0l4Q3pBSkJnTlYKQkFZVEFsVlRNUk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIREExVFlXNGdSbkpoYm1OcApjMk52TVE4d0RRWURWUVFLREFaQ1lXUlRVMHd4RlRBVEJnTlZCQU1NRENvdVltRmtjM05zTG1OdmJUQWVGdzB4Ck9UQTJNVEl4TlRNeE5UbGFGdzB5TVRBMk1URXhOVE14TlRsYU1HSXhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWUQKVlFRSURBcERZV3hwWm05eWJtbGhNUll3RkFZRFZRUUhEQTFUWVc0Z1JuSmhibU5wYzJOdk1ROHdEUVlEVlFRSwpEQVpDWVdSVFUwd3hGVEFUQmdOVkJBTU1EQ291WW1Ga2MzTnNMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCCkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1JRTdQaU03Z1RDczloUTFYQll6Sk1ZNjF5b2FFbXdJclg1bFo2eEt5eDIKUG16QVMyQk1UT3F5dE1BUGdMYXcrWExKaGdMNVhFRmRFeXQvY2NSTHZPbVVMbEEzcG1jY1lZejJRVUxGUnRNVwpoeWVmZE9zS25SRlNKaUZ6YklSTWVWWGswV3ZvQmoxSUZWS3RzeWpicXY5dS8yQ1ZTbmRyT2ZFazBURzIzVTNBCnhQeFR1VzFDcmJWOC9xNzFGZEl6U09jaWNjZkNGSHBzS09vM1N0L3FiTFZ5dEg1YW9oYmNhYkZYUk5zS0VxdmUKd3c5SGRGeEJJdUdhK1J1VDVxMGlCaWt1c2JwSkhBd25ucVA3aS9kQWNnQ3NrZ2paakZlRVU0RUZ5K2IrYTFTWQpRQ2VGeHhDN2MzRHZhUmhCQjBWVmZQbGtQejBzdzZsODY1TWFUSWJSeW9VQ0F3RUFBYU15TURBd0NRWURWUjBUCkJBSXdBREFqQmdOVkhSRUVIREFhZ2d3cUxtSmhaSE56YkM1amIyMkNDbUpoWkhOemJDNWpiMjB3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dFQkFJaTV1OXc4bWdUNnBwQ2M3eHNHK0E5ZkkzVzR6K3FTS2FwaHI1bHM3MEdCS2JpWQpZTEpVWVpoUGZXcGgxcXRra1UwTEhGUG04M1ZhNTJlSUhyalhUMFZlNEt0TzFuMElBZkl0RmFXNjJDSmdoR1luCmp6dzByeXpnQzRQeUZwTk1uTnRCcm9QdS9iUGdXaU1nTE9OcEVaaGlneDRROHdmMVkvVTlzK3pDQ3hvSmxhS1IKTVhidVE4N1g3bS85VlJueHhvNk56NVpmN09USFRwTk9JNlZqYTBCeGJtSUFVNnlyaXc5VXJnaWJYZk9qM2o2bgpNVExCdWdVVklCMGJCYWFzSnNBTUsrdzRMQU52YXBlWjBET1NuT1I0S0syNEowT3lvRjVmSG1wNTllTTE3SW9GClFxQmh6cG1RVWd1bmVjRVc4QlRxck5wRzc5UjF1K1YrNHd3Y2tQYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}
	customCAPolicies := testOptions(t)
	customCAPolicies.Policies = []config.Policy{
		customCAPolicy,
	}
	badCustomCAPolicy := config.Policy{To: "http://foo.example", From: "http://bar.example", TLSCustomCA: "=@@"}
	badCustomCAPolicies := testOptions(t)
	badCustomCAPolicies.Policies = []config.Policy{
		badCustomCAPolicy,
	}
	tests := []struct {
		name            string
		originalOptions config.Options
		updatedOptions  config.Options
		signingKey      string
		host            string
		wantErr         bool
		wantRoute       bool
	}{
		{"good no change", good, good, "", "https://corp.example.example", false, true},
		{"changed", good, newPolicies, "", "https://bar.example", false, true},
		{"changed and missing", good, newPolicies, "", "https://corp.example.example", false, false},
		// todo(bdd): not sure what intent of this test is?
		{"bad signing key", good, newPolicies, "^bad base 64", "https://corp.example.example", true, false},
		{"bad change bad policy url", good, badNewPolicy, "", "https://bar.example", true, false},
		// todo: stand up a test server using self signed certificates
		{"disable tls verification", good, disableTLSPolicies, "", "https://bar.example", false, true},
		{"custom root ca", good, customCAPolicies, "", "https://bar.example", false, true},
		{"bad custom root ca base64", good, badCustomCAPolicies, "", "https://bar.example", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.originalOptions)
			if err != nil {
				t.Fatal(err)
			}

			p.signingKey = tt.signingKey
			err = p.UpdateOptions(tt.updatedOptions)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateOptions: err = %v, wantErr = %v", err, tt.wantErr)
				return
			}

			// This is only safe if we actually can load policies
			if err == nil {
				req := httptest.NewRequest("GET", tt.host, nil)
				_, ok := p.router(req)
				if ok != tt.wantRoute {
					t.Errorf("Failed to find route handler")
					return
				}
			}
		})
	}

	// Test nil
	var p *Proxy
	p.UpdateOptions(config.Options{})
}
