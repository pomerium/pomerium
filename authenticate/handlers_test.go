package authenticate

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pomerium/pomerium/authenticate/providers"
	"github.com/pomerium/pomerium/internal/templates"
)

func testAuthenticate() *Authenticate {
	var auth Authenticate
	auth.RedirectURL, _ = url.Parse("https://auth.example.com/oauth/callback")
	auth.SharedKey = "IzY7MOZwzfOkmELXgozHDKTxoT3nOYhwkcmUVINsRww="
	auth.AllowedDomains = []string{"*"}
	auth.ProxyRootDomains = []string{"example.com"}
	auth.templates = templates.New()
	auth.provider = providers.NewTestProvider(auth.RedirectURL)
	return &auth
}

func TestAuthenticate_PingPage(t *testing.T) {
	auth := testAuthenticate()
	req, err := http.NewRequest("GET", "/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.PingPage)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := "OK"
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestAuthenticate_RobotsTxt(t *testing.T) {
	auth := testAuthenticate()
	req, err := http.NewRequest("GET", "/robots.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.RobotsTxt)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)

	}
}

func TestAuthenticate_SignInPage(t *testing.T) {
	auth := testAuthenticate()
	v := url.Values{}
	v.Set("request_uri", "this-is-a-test-uri")
	url := fmt.Sprintf("/signin?%s", v.Encode())

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.SignInPage)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	body := rr.Body.Bytes()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"provider name", auth.provider.Data().ProviderName, true},
		{"destination url", v.Encode(), true},
		{"shouldn't be found", "this string should not be in the body", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytes.Contains(body, []byte(tt.value)); got != tt.want {
				t.Errorf("handler body missing expected value %v", tt.value)
			}
		})
	}
}
